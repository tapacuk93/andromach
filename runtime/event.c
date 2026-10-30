// Event files: epoll, eventfd, timerfd, signalfd, memfd, inotify, and pselect6.
//
// Every one of them has a host fd that host poll() understands, so ppoll, pselect6 and epoll see
// their readiness: a socketpair end that holds one byte while the object is ready. Darwin's
// poll() rejects kqueue fds, so epoll's kqueue lives beside its host fd rather than being it.
#include "am.h"
#include "linux.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define EPOLLIN 0x1
#define EPOLLPRI 0x2
#define EPOLLOUT 0x4
#define EPOLLERR 0x8
#define EPOLLHUP 0x10
#define EPOLLRDNORM 0x40
#define EPOLLWRNORM 0x100
#define EPOLLRDHUP 0x2000
#define EPOLLONESHOT (1u << 30)
#define EPOLLET (1u << 31)
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

struct linux_epoll_event { uint32_t events; uint32_t pad; uint64_t data; };  // not packed on arm64
struct linux_itimerspec { struct linux_timespec interval, value; };

// A socketpair: [0] becomes the file's host fd, [1] is where readiness bytes are written.
static int ready_pair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return am_errno(errno);
    int one = 1;
    for (int i = 0; i < 2; i++) {
        fcntl(sv[i], F_SETFD, FD_CLOEXEC);
        setsockopt(sv[i], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    }
    return 0;
}

static bool nonblocking(am_file *f) { return fcntl(f->hostfd, F_GETFL) & O_NONBLOCK; }

static void set_ready(int wr) { (void)send(wr, "", 1, MSG_DONTWAIT); }
static void clear_ready(int rd) { char b[16]; (void)recv(rd, b, sizeof b, MSG_DONTWAIT); }

// Blocks until the host fd is readable (the object may still be taken by another reader).
static void wait_readable(int fd) {
    struct pollfd p = {fd, POLLIN, 0};
    while (poll(&p, 1, -1) < 0 && errno == EINTR) {}
}

static long install(am_file *f, int lflags) {
    if (lflags & LINUX_O_NONBLOCK) fcntl(f->hostfd, F_SETFL, O_NONBLOCK);
    long fd = am_fd_install(am_self->proc, f, 0, lflags & LINUX_O_CLOEXEC);
    if (fd < 0) am_file_put(f);
    return fd;
}

// ---- eventfd -----------------------------------------------------------------------------
typedef struct { pthread_mutex_t lock; uint64_t count; bool sem; int wr; } efd;

static long efd_read(am_file *f, void *buf, size_t n) {
    efd *e = f->priv;
    if (n < 8) return AM_ERR(LINUX_EINVAL);
    for (;;) {
        pthread_mutex_lock(&e->lock);
        if (e->count) {
            uint64_t v = e->sem ? 1 : e->count;
            e->count -= v;
            if (!e->count) clear_ready(f->hostfd);
            pthread_mutex_unlock(&e->lock);
            memcpy(buf, &v, 8);
            return 8;
        }
        pthread_mutex_unlock(&e->lock);
        if (nonblocking(f)) return AM_ERR(LINUX_EAGAIN);
        wait_readable(f->hostfd);
    }
}

static long efd_write(am_file *f, const void *buf, size_t n) {
    efd *e = f->priv;
    uint64_t v;
    if (n < 8) return AM_ERR(LINUX_EINVAL);
    memcpy(&v, buf, 8);
    if (v == ~0ull) return AM_ERR(LINUX_EINVAL);
    for (;;) {
        pthread_mutex_lock(&e->lock);
        if (e->count + v >= e->count && e->count + v != ~0ull) {
            if (!e->count && v) set_ready(e->wr);
            e->count += v;
            pthread_mutex_unlock(&e->lock);
            return 8;
        }
        pthread_mutex_unlock(&e->lock);
        // Would overflow: Linux blocks until a reader takes the count. Nothing signals that, so
        // poll for it; real programs never get here.
        if (nonblocking(f)) return AM_ERR(LINUX_EAGAIN);
        usleep(1000);
    }
}

static void efd_release(am_file *f) {
    efd *e = f->priv;
    close(e->wr);
    pthread_mutex_destroy(&e->lock);
    free(e);
}

static const am_file_ops efd_ops = {.name = "eventfd", .read = efd_read, .write = efd_write, .release = efd_release};

static long do_eventfd(unsigned initval, int flags) {
    if (flags & ~(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC | 1)) return AM_ERR(LINUX_EINVAL);
    int sv[2];
    long r = ready_pair(sv);
    if (r) return r;
    efd *e = calloc(1, sizeof *e);
    pthread_mutex_init(&e->lock, NULL);
    e->count = initval;
    e->sem = flags & 1;  // EFD_SEMAPHORE
    e->wr = sv[1];
    if (initval) set_ready(e->wr);
    return install(am_file_new(sv[0], LINUX_O_RDWR, "anon_inode:[eventfd]", &efd_ops, e), flags);
}

// ---- timerfd -----------------------------------------------------------------------------
// One host thread waits on a kqueue holding every armed timer; when one fires it marks that
// timerfd ready. Expirations are counted from the clock when the guest reads, so a late wakeup
// loses nothing.
typedef struct tfd {
    struct tfd *next;
    uint64_t id;
    clockid_t clock;
    int64_t next_ns, interval_ns;  // next expiry on `clock`; 0 = disarmed
    bool ready;
    int wr;
} tfd;

static pthread_mutex_t tlock = PTHREAD_MUTEX_INITIALIZER;
static tfd *timers;
static uint64_t timer_ids;
static int tkq = -1;

static int64_t now_ns(clockid_t c) { return (int64_t)clock_gettime_nsec_np(c); }

// Points the host timer at t's next expiry. Called with tlock held.
static void timer_arm(tfd *t) {
    struct kevent ev;
    if (!t->next_ns) {
        EV_SET(&ev, t->id, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
    } else {
        int64_t d = t->next_ns - now_ns(t->clock);
        // NOTE_CRITICAL: no coalescing, which would otherwise delay timers by hundreds of ms.
        EV_SET(&ev, t->id, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_NSECONDS | NOTE_CRITICAL, d > 0 ? d : 1, NULL);
    }
    kevent(tkq, &ev, 1, NULL, 0, NULL);
}

static void *timer_thread(void *arg) {
    pthread_setname_np("andromach-timerfd");
    for (;;) {
        struct kevent ev[16];
        int n = kevent(tkq, NULL, 0, ev, 16, NULL);
        pthread_mutex_lock(&tlock);
        for (int i = 0; i < n; i++)
            for (tfd *t = timers; t; t = t->next) {
                if (t->id != ev[i].ident) continue;
                if (!t->next_ns) break;
                if (now_ns(t->clock) >= t->next_ns) {
                    if (!t->ready) { t->ready = true; set_ready(t->wr); }
                } else {
                    timer_arm(t);  // the host timer ran on a slightly different clock
                }
                break;
            }
        pthread_mutex_unlock(&tlock);
    }
    return NULL;
}

static void timer_start(void) {
    tkq = kqueue();
    pthread_t th;
    pthread_create(&th, NULL, timer_thread, NULL);
    pthread_detach(th);
}

// Expirations due by now, advancing t past them. Called with tlock held.
static uint64_t timer_take(tfd *t) {
    if (!t->next_ns) return 0;
    int64_t now = now_ns(t->clock);
    if (now < t->next_ns) return 0;
    uint64_t n = 1;
    if (t->interval_ns) {
        n += (uint64_t)(now - t->next_ns) / (uint64_t)t->interval_ns;
        t->next_ns += (int64_t)n * t->interval_ns;
    } else {
        t->next_ns = 0;
    }
    return n;
}

static long tfd_read(am_file *f, void *buf, size_t n) {
    tfd *t = f->priv;
    if (n < 8) return AM_ERR(LINUX_EINVAL);
    for (;;) {
        pthread_mutex_lock(&tlock);
        uint64_t exp = timer_take(t);
        if (exp) {
            if (t->ready) { t->ready = false; clear_ready(f->hostfd); }
            timer_arm(t);
        }
        pthread_mutex_unlock(&tlock);
        if (exp) { memcpy(buf, &exp, 8); return 8; }
        if (nonblocking(f)) return AM_ERR(LINUX_EAGAIN);
        wait_readable(f->hostfd);
    }
}

static void tfd_release(am_file *f) {
    tfd *t = f->priv;
    pthread_mutex_lock(&tlock);
    for (tfd **pp = &timers; *pp; pp = &(*pp)->next)
        if (*pp == t) { *pp = t->next; break; }
    t->next_ns = 0;
    timer_arm(t);
    pthread_mutex_unlock(&tlock);
    close(t->wr);
    free(t);
}

static const am_file_ops tfd_ops = {.name = "timerfd", .read = tfd_read, .release = tfd_release};

static clockid_t timer_clock(int id) {
    switch (id) {
    case 0: case 8: return CLOCK_REALTIME;     // REALTIME, REALTIME_ALARM
    case 1: return CLOCK_UPTIME_RAW;           // MONOTONIC: stops in sleep
    case 7: case 9: return CLOCK_MONOTONIC;    // BOOTTIME, BOOTTIME_ALARM: counts sleep
    }
    return (clockid_t)-1;
}

static long do_timerfd_create(int clock, int flags) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    clockid_t c = timer_clock(clock);
    if (c == (clockid_t)-1) return AM_ERR(LINUX_EINVAL);
    if (flags & ~(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC)) return AM_ERR(LINUX_EINVAL);
    pthread_once(&once, timer_start);
    int sv[2];
    long r = ready_pair(sv);
    if (r) return r;
    tfd *t = calloc(1, sizeof *t);
    t->clock = c;
    t->wr = sv[1];
    pthread_mutex_lock(&tlock);
    t->id = ++timer_ids;
    t->next = timers;
    timers = t;
    pthread_mutex_unlock(&tlock);
    return install(am_file_new(sv[0], LINUX_O_RDWR, "anon_inode:[timerfd]", &tfd_ops, t), flags);
}

static int64_t ts_ns(const struct linux_timespec *ts) { return ts->tv_sec * 1000000000ll + ts->tv_nsec; }
static struct linux_timespec ns_ts(int64_t ns) { return (struct linux_timespec){ns / 1000000000, ns % 1000000000}; }

// Current setting, as timerfd_gettime reports it. Called with tlock held.
static void timer_get(tfd *t, struct linux_itimerspec *out) {
    int64_t left = 0;
    if (t->next_ns) {
        left = t->next_ns - now_ns(t->clock);
        if (left <= 0) left = t->interval_ns ? t->interval_ns - (-left % t->interval_ns) : 1;
    }
    out->interval = ns_ts(t->interval_ns);
    out->value = ns_ts(left);
}

static long do_timerfd_settime(int fd, int flags, const struct linux_itimerspec *nv, struct linux_itimerspec *old) {
    am_file *f = am_fd_get(fd);
    if (!f) return AM_ERR(LINUX_EBADF);
    if (f->ops != &tfd_ops) return AM_ERR(LINUX_EINVAL);
    if (nv->value.tv_nsec < 0 || nv->value.tv_nsec >= 1000000000 || nv->interval.tv_nsec < 0 ||
        nv->interval.tv_nsec >= 1000000000)
        return AM_ERR(LINUX_EINVAL);
    tfd *t = f->priv;
    pthread_mutex_lock(&tlock);
    if (old) timer_get(t, old);
    int64_t v = ts_ns(&nv->value);
    if (!v) t->next_ns = 0;
    else if (flags & 1) t->next_ns = v ? v : 1;  // TFD_TIMER_ABSTIME
    else t->next_ns = now_ns(t->clock) + v;
    t->interval_ns = ts_ns(&nv->interval);
    if (t->ready) { t->ready = false; clear_ready(f->hostfd); }  // a new setting drops pending expirations
    timer_arm(t);
    pthread_mutex_unlock(&tlock);
    return 0;
}

static long do_timerfd_gettime(int fd, struct linux_itimerspec *out) {
    am_file *f = am_fd_get(fd);
    if (!f) return AM_ERR(LINUX_EBADF);
    if (f->ops != &tfd_ops) return AM_ERR(LINUX_EINVAL);
    pthread_mutex_lock(&tlock);
    timer_get(f->priv, out);
    pthread_mutex_unlock(&tlock);
    return 0;
}

// ---- signalfd, inotify -------------------------------------------------------------------
// Valid files that never become readable: signal delivery and file watching come later.
typedef struct { int wr; uint64_t mask; int wds; } quiet;

static void quiet_release(am_file *f) {
    quiet *q = f->priv;
    close(q->wr);
    free(q);
}

static const am_file_ops signalfd_ops = {.name = "signalfd", .release = quiet_release};
static const am_file_ops inotify_ops = {.name = "inotify", .release = quiet_release};

static long quiet_new(const am_file_ops *ops, const char *gpath, int flags, quiet **out) {
    int sv[2];
    long r = ready_pair(sv);
    if (r) return r;
    quiet *q = calloc(1, sizeof *q);
    q->wr = sv[1];
    *out = q;
    return install(am_file_new(sv[0], LINUX_O_RDONLY, gpath, ops, q), flags);
}

static long do_signalfd(int fd, const uint64_t *mask, size_t size, int flags) {
    if (size != 8 || (flags & ~(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC))) return AM_ERR(LINUX_EINVAL);
    quiet *q;
    if (fd != -1) {
        am_file *f = am_fd_get(fd);
        if (!f) return AM_ERR(LINUX_EBADF);
        if (f->ops != &signalfd_ops) return AM_ERR(LINUX_EINVAL);
        ((quiet *)f->priv)->mask = *mask;
        return fd;
    }
    long r = quiet_new(&signalfd_ops, "anon_inode:[signalfd]", flags, &q);
    if (r >= 0) q->mask = *mask;
    return r;
}

// ---- memfd -------------------------------------------------------------------------------
// An unlinked file in the data directory: mmap(MAP_SHARED) of it is shared by every guest
// process that maps it, since they all live in this one host process.
static long do_memfd_create(const char *name, unsigned flags) {
    if (flags & ~0x1Fu) return AM_ERR(LINUX_EINVAL);  // CLOEXEC, ALLOW_SEALING, HUGETLB, NOEXEC_SEAL, EXEC
    char path[4096], gpath[300];
    snprintf(path, sizeof path, "%s/tmp/.memfd-XXXXXX", am_datadir);
    int fd = mkstemp(path);
    if (fd < 0) return am_errno(errno);
    unlink(path);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    snprintf(gpath, sizeof gpath, "/memfd:%.249s (deleted)", name);
    return install(am_file_new(fd, LINUX_O_RDWR, gpath, NULL, NULL), (flags & 1) ? LINUX_O_CLOEXEC : 0);
}

// ---- epoll -------------------------------------------------------------------------------
// A kqueue per epoll file. A registration watches the target's host fd with EVFILT_READ and/or
// EVFILT_WRITE, its kevent udata naming the registration by id so that a stale event for a
// deleted one is dropped. EPOLLET maps to EV_CLEAR; EPOLLONESHOT disables both filters once
// one has been reported, until EPOLL_CTL_MOD.
typedef struct ereg {
    struct ereg *next;
    uint64_t id;
    am_file *f;       // no reference: am_event_file_gone removes it when the file goes away
    int fd;
    int ident;        // the host fd the filters are on
    uint32_t events;
    uint64_t data;
    bool disabled;
} ereg;

typedef struct epoll {
    struct epoll *gnext;
    pthread_mutex_t lock;
    int kq;
    int wr;           // the other end of the file's (never readable) host fd
    ereg *regs;
    uint64_t ids;
} epoll;

static pthread_mutex_t elock = PTHREAD_MUTEX_INITIALIZER;  // the list of epoll sets
static epoll *epolls;
static int nregs;  // registrations in all sets: closing a file skips the scan while it is 0

static const am_file_ops epoll_ops;

// What kqueue watches for a file. A nested epoll is watched through its kqueue, which kqueue
// (unlike poll) can wait on.
static int ident_of(am_file *f) {
    return f->ops == &epoll_ops ? ((epoll *)f->priv)->kq : f->hostfd;
}

// Installs r's filters in the kqueue. Called with ep->lock held. Returns 0 or -errno.
static long ereg_apply(epoll *ep, ereg *r) {
    struct kevent kev[2], out[2];
    uint16_t on = EV_ADD | EV_RECEIPT | (r->events & EPOLLET ? EV_CLEAR : 0) | (r->disabled ? EV_DISABLE : EV_ENABLE);
    void *ud = (void *)(uintptr_t)r->id;
    bool rd = r->events & (EPOLLIN | EPOLLRDNORM | EPOLLRDHUP | EPOLLPRI);
    bool wr = r->events & (EPOLLOUT | EPOLLWRNORM);
    EV_SET(&kev[0], r->ident, EVFILT_READ, rd ? on : EV_DELETE | EV_RECEIPT, 0, 0, ud);
    EV_SET(&kev[1], r->ident, EVFILT_WRITE, wr ? on : EV_DELETE | EV_RECEIPT, 0, 0, ud);
    int n = kevent(ep->kq, kev, 2, out, 2, NULL);
    if (n < 0) return am_errno(errno);
    for (int i = 0; i < n; i++)
        if ((out[i].flags & EV_ERROR) && out[i].data && !(kev[i].flags & EV_DELETE)) {
            // Regular files and directories have no write filter; Linux refuses them outright.
            return out[i].data == EINVAL ? AM_ERR(LINUX_EPERM) : am_errno((int)out[i].data);
        }
    return 0;
}

static void ereg_clear(epoll *ep, ereg *r) {
    struct kevent kev[2];
    EV_SET(&kev[0], r->ident, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    EV_SET(&kev[1], r->ident, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    for (int i = 0; i < 2; i++) kevent(ep->kq, &kev[i], 1, NULL, 0, NULL);
}

static void ereg_remove(epoll *ep, ereg **pp) {
    ereg *r = *pp;
    ereg_clear(ep, r);
    *pp = r->next;
    free(r);
    __atomic_sub_fetch(&nregs, 1, __ATOMIC_RELAXED);
}

void am_event_file_gone(am_file *f) {
    if (!__atomic_load_n(&nregs, __ATOMIC_RELAXED)) return;
    pthread_mutex_lock(&elock);
    for (epoll *ep = epolls; ep; ep = ep->gnext) {
        pthread_mutex_lock(&ep->lock);
        for (ereg **pp = &ep->regs; *pp;) {
            if ((*pp)->f == f) ereg_remove(ep, pp);
            else pp = &(*pp)->next;
        }
        pthread_mutex_unlock(&ep->lock);
    }
    pthread_mutex_unlock(&elock);
}

void am_event_hostfd_changed(am_file *f) {
    if (!__atomic_load_n(&nregs, __ATOMIC_RELAXED)) return;
    pthread_mutex_lock(&elock);
    for (epoll *ep = epolls; ep; ep = ep->gnext) {
        pthread_mutex_lock(&ep->lock);
        for (ereg *r = ep->regs; r; r = r->next)
            if (r->f == f) { r->ident = ident_of(f); ereg_apply(ep, r); }
        pthread_mutex_unlock(&ep->lock);
    }
    pthread_mutex_unlock(&elock);
}

static void epoll_release(am_file *f) {
    epoll *ep = f->priv;
    pthread_mutex_lock(&elock);
    for (epoll **pp = &epolls; *pp; pp = &(*pp)->gnext)
        if (*pp == ep) { *pp = ep->gnext; break; }
    pthread_mutex_unlock(&elock);
    while (ep->regs) {
        ereg *r = ep->regs;
        ep->regs = r->next;
        free(r);
        __atomic_sub_fetch(&nregs, 1, __ATOMIC_RELAXED);
    }
    close(ep->kq);
    close(ep->wr);
    pthread_mutex_destroy(&ep->lock);
    free(ep);
}

static const am_file_ops epoll_ops = {.name = "epoll", .release = epoll_release};

static long do_epoll_create(int flags) {
    if (flags & ~LINUX_O_CLOEXEC) return AM_ERR(LINUX_EINVAL);
    int sv[2];
    long r = ready_pair(sv);
    if (r) return r;
    epoll *ep = calloc(1, sizeof *ep);
    pthread_mutex_init(&ep->lock, NULL);
    ep->kq = kqueue();
    fcntl(ep->kq, F_SETFD, FD_CLOEXEC);
    ep->wr = sv[1];
    pthread_mutex_lock(&elock);
    ep->gnext = epolls;
    epolls = ep;
    pthread_mutex_unlock(&elock);
    return install(am_file_new(sv[0], LINUX_O_RDWR, "anon_inode:[eventpoll]", &epoll_ops, ep), flags);
}

static long do_epoll_ctl(int epfd, int op, int fd, const struct linux_epoll_event *ev) {
    am_file *ef = am_fd_get(epfd), *f = am_fd_get(fd);
    if (!ef || !f) return AM_ERR(LINUX_EBADF);
    if (ef->ops != &epoll_ops || ef == f) return AM_ERR(LINUX_EINVAL);
    epoll *ep = ef->priv;
    long r = 0;
    pthread_mutex_lock(&ep->lock);
    ereg **pp = &ep->regs;
    while (*pp && !((*pp)->f == f && (*pp)->fd == fd)) pp = &(*pp)->next;
    switch (op) {
    case EPOLL_CTL_ADD: {
        if (*pp) { r = AM_ERR(LINUX_EEXIST); break; }
        ereg *n = calloc(1, sizeof *n);
        n->id = ++ep->ids;
        n->f = f;
        n->fd = fd;
        n->ident = ident_of(f);
        n->events = ev->events;
        n->data = ev->data;
        if ((r = ereg_apply(ep, n))) { free(n); break; }
        n->next = ep->regs;
        ep->regs = n;
        __atomic_add_fetch(&nregs, 1, __ATOMIC_RELAXED);
        break;
    }
    case EPOLL_CTL_MOD:
        if (!*pp) { r = AM_ERR(LINUX_ENOENT); break; }
        // kqueue keeps EV_CLEAR across a modify, so start the filters afresh.
        ereg_clear(ep, *pp);
        (*pp)->events = ev->events;
        (*pp)->data = ev->data;
        (*pp)->disabled = false;
        r = ereg_apply(ep, *pp);
        break;
    case EPOLL_CTL_DEL:
        if (!*pp) { r = AM_ERR(LINUX_ENOENT); break; }
        ereg_remove(ep, pp);
        break;
    default:
        r = AM_ERR(LINUX_EINVAL);
    }
    pthread_mutex_unlock(&ep->lock);
    return r;
}

// Linux event bits for one kevent of registration r.
static uint32_t ev_bits(const ereg *r, const struct kevent *k) {
    uint32_t b = 0;
    if (k->filter == EVFILT_READ) {
        b |= EPOLLIN | EPOLLRDNORM;
        if (k->flags & EV_EOF) {
            // Darwin cannot tell a half-close from a full one, which Linux reports as HUP.
            b |= EPOLLRDHUP;
            if (am_sock_peer_gone(r->f)) b |= EPOLLHUP;
            if (k->fflags) b |= EPOLLERR;
        }
    } else if (k->filter == EVFILT_WRITE) {
        b |= EPOLLOUT | EPOLLWRNORM;
        if (k->flags & EV_EOF) b |= EPOLLHUP | (k->fflags ? EPOLLERR : 0);
    }
    if (k->flags & EV_ERROR) b |= EPOLLERR;
    return b & (r->events | EPOLLERR | EPOLLHUP);
}

static long do_epoll_wait(int epfd, struct linux_epoll_event *out, int max, int64_t timeout_ns) {
    am_file *ef = am_fd_get(epfd);
    if (!ef) return AM_ERR(LINUX_EBADF);
    if (ef->ops != &epoll_ops || max <= 0) return AM_ERR(LINUX_EINVAL);
    epoll *ep = ef->priv;
    // No more kevents than the guest has room for: with EV_CLEAR an event taken off the queue
    // and not reported would be lost.
    int cap = max < 256 ? max : 256;
    struct kevent kev[cap];
    int64_t deadline = timeout_ns >= 0 ? now_ns(CLOCK_UPTIME_RAW) + timeout_ns : 0;
    for (;;) {
        struct timespec ts, *tp = NULL;
        if (timeout_ns >= 0) {
            int64_t left = deadline - now_ns(CLOCK_UPTIME_RAW);
            if (left < 0) left = 0;
            ts = (struct timespec){left / 1000000000, left % 1000000000};
            tp = &ts;
        }
        int n = kevent(ep->kq, NULL, 0, kev, cap, tp);
        if (n < 0) {
            if (errno == EINTR) continue;
            return am_errno(errno);
        }
        int got = 0;
        ereg *who[cap];
        pthread_mutex_lock(&ep->lock);
        for (int i = 0; i < n; i++) {
            ereg *r = ep->regs;
            while (r && r->id != (uint64_t)(uintptr_t)kev[i].udata) r = r->next;
            if (!r || r->disabled) continue;
            uint32_t b = ev_bits(r, &kev[i]);
            if (!b) continue;
            int j = 0;
            while (j < got && who[j] != r) j++;  // both filters fired: one event
            if (j == got) {
                who[got++] = r;
                out[j] = (struct linux_epoll_event){0, 0, r->data};
            }
            out[j].events |= b;
        }
        for (int j = 0; j < got; j++)
            if (who[j]->events & EPOLLONESHOT) {
                who[j]->disabled = true;
                ereg_apply(ep, who[j]);
            }
        pthread_mutex_unlock(&ep->lock);
        if (got || n == 0) return got;
        // Every event was filtered out (a stale or masked one): wait again.
        if (timeout_ns >= 0 && now_ns(CLOCK_UPTIME_RAW) >= deadline) return 0;
    }
}

// ---- pselect6 ----------------------------------------------------------------------------
static long do_pselect(int n, uint64_t *rd, uint64_t *wr, uint64_t *ex, struct linux_timespec *tmo) {
    if (n < 0 || n > AM_MAX_FDS) return AM_ERR(LINUX_EINVAL);
    struct pollfd p[n ? n : 1];
    int fds[n ? n : 1], np = 0;
    for (int fd = 0; fd < n; fd++) {
        uint64_t bit = 1ull << (fd % 64);
        int w = fd / 64;
        short ev = 0;
        if (rd && (rd[w] & bit)) ev |= POLLIN;
        if (wr && (wr[w] & bit)) ev |= POLLOUT;
        if (ex && (ex[w] & bit)) ev |= POLLPRI;
        if (!ev) continue;
        am_file *f = am_fd_get(fd);
        if (!f) return AM_ERR(LINUX_EBADF);
        p[np] = (struct pollfd){f->hostfd, ev, 0};
        fds[np++] = fd;
    }
    int64_t t0 = now_ns(CLOCK_UPTIME_RAW);
    int ms = tmo ? (int)((ts_ns(tmo) + 999999) / 1000000) : -1;
    int r = poll(p, np, ms);
    if (r < 0) return am_errno(errno);
    int words = (n + 63) / 64;
    if (rd) memset(rd, 0, words * 8);
    if (wr) memset(wr, 0, words * 8);
    if (ex) memset(ex, 0, words * 8);
    int count = 0;
    for (int i = 0; i < np; i++) {
        uint64_t bit = 1ull << (fds[i] % 64);
        int w = fds[i] / 64;
        short re = p[i].revents;
        if (rd && (p[i].events & POLLIN) && (re & (POLLIN | POLLHUP | POLLERR))) { rd[w] |= bit; count++; }
        if (wr && (p[i].events & POLLOUT) && (re & (POLLOUT | POLLERR))) { wr[w] |= bit; count++; }
        if (ex && (p[i].events & POLLPRI) && (re & POLLPRI)) { ex[w] |= bit; count++; }
    }
    if (tmo) {
        int64_t left = ts_ns(tmo) - (now_ns(CLOCK_UPTIME_RAW) - t0);
        *tmo = ns_ts(left > 0 ? left : 0);
    }
    return count;
}

// ---- system calls ------------------------------------------------------------------------
long sys_event(am_ctx *c, long nr, bool *handled) {
#define A(i) (c->x[i])
    *handled = true;
    switch (nr) {
    case LINUX_SYS_eventfd2: return do_eventfd((unsigned)A(0), (int)A(1));
    case LINUX_SYS_epoll_create1: return do_epoll_create((int)A(0));
    case LINUX_SYS_epoll_ctl: return do_epoll_ctl((int)A(0), (int)A(1), (int)A(2), (void *)A(3));
    case LINUX_SYS_epoll_pwait: {
        // The signal mask would apply while waiting; signals are not delivered yet.
        int ms = (int)A(3);
        return do_epoll_wait((int)A(0), (void *)A(1), (int)A(2), ms < 0 ? -1 : ms * 1000000ll);
    }
    case LINUX_SYS_epoll_pwait2: {
        const struct linux_timespec *ts = (void *)A(3);
        return do_epoll_wait((int)A(0), (void *)A(1), (int)A(2), ts ? ts_ns(ts) : -1);
    }
    case LINUX_SYS_timerfd_create: return do_timerfd_create((int)A(0), (int)A(1));
    case LINUX_SYS_timerfd_settime: return do_timerfd_settime((int)A(0), (int)A(1), (void *)A(2), (void *)A(3));
    case LINUX_SYS_timerfd_gettime: return do_timerfd_gettime((int)A(0), (void *)A(1));
    case LINUX_SYS_signalfd4: return do_signalfd((int)A(0), (void *)A(1), A(2), (int)A(3));
    case LINUX_SYS_memfd_create: return do_memfd_create((const char *)A(0), (unsigned)A(1));
    case LINUX_SYS_inotify_init1: {
        if (A(0) & ~(uint64_t)(LINUX_O_NONBLOCK | LINUX_O_CLOEXEC)) return AM_ERR(LINUX_EINVAL);
        quiet *q;
        return quiet_new(&inotify_ops, "anon_inode:inotify", (int)A(0), &q);
    }
    case LINUX_SYS_inotify_add_watch: {
        am_file *f = am_fd_get((int)A(0));
        if (!f) return AM_ERR(LINUX_EBADF);
        if (f->ops != &inotify_ops) return AM_ERR(LINUX_EINVAL);
        char host[4096];
        long r = am_resolve(LINUX_AT_FDCWD, (const char *)A(1), !(A(2) & 0x01000000), host, sizeof host, NULL, 0);
        if (r < 0) return r;
        if (access(host, F_OK)) return am_errno(errno);
        return __atomic_add_fetch(&((quiet *)f->priv)->wds, 1, __ATOMIC_RELAXED);
    }
    case LINUX_SYS_inotify_rm_watch: {
        am_file *f = am_fd_get((int)A(0));
        if (!f) return AM_ERR(LINUX_EBADF);
        return f->ops == &inotify_ops ? 0 : AM_ERR(LINUX_EINVAL);
    }
    case LINUX_SYS_pselect6:
        return do_pselect((int)A(0), (void *)A(1), (void *)A(2), (void *)A(3), (void *)A(4));
    }
    *handled = false;
    return 0;
#undef A
}
