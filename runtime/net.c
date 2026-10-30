// Sockets: AF_UNIX (stream, dgram, seqpacket; filesystem and abstract names; SCM_RIGHTS,
// SCM_CREDENTIALS), AF_INET/AF_INET6 over the host's sockets, and a netlink socket whose dumps
// are empty.
//
// Every guest process lives in this one host process, so AF_UNIX is ours to implement: names
// live in a registry here (no sun_path length limit, abstract names work), and each connection
// is a host socketpair, which keeps poll and kqueue readiness exact.
//
//   SOCK_STREAM     a host stream socketpair; bytes pass through untouched.
//   SOCK_SEQPACKET  a host stream socketpair carrying framed messages: Darwin has no
//                   AF_UNIX seqpacket, and its datagram socketpairs never report the peer's
//                   close, which Android relies on.
//   SOCK_DGRAM      every socket has an inbox (a host datagram socketpair); senders write
//                   [header][payload] datagrams into the inbox of the socket they address.
//
// Passed fds travel as references to the guest's am_file: the sender parks them in an in-flight
// table under an id, and the id travels with the data (in the frame or datagram header, or for
// stream sockets in a small tag socket passed with host SCM_RIGHTS so the kernel keeps them
// attached to the right bytes).
#include "am.h"
#include "linux.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#define LINUX_ENOTSOCK 88
#define LINUX_EDESTADDRREQ 89
#define LINUX_EMSGSIZE 90
#define LINUX_EPROTOTYPE 91
#define LINUX_ENOPROTOOPT 92
#define LINUX_EPROTONOSUPPORT 93
#define LINUX_EOPNOTSUPP 95
#define LINUX_EAFNOSUPPORT 97
#define LINUX_EADDRINUSE 98
#define LINUX_ENETDOWN 100
#define LINUX_EISCONN 106
#define LINUX_ENOTCONN 107
#define LINUX_ECONNREFUSED 111
#define LINUX_ENODEV 19
#define LINUX_EPIPE 32

#define L_AF_UNSPEC 0
#define L_AF_UNIX 1
#define L_AF_INET 2
#define L_AF_INET6 10
#define L_AF_NETLINK 16

#define L_SOCK_STREAM 1
#define L_SOCK_DGRAM 2
#define L_SOCK_RAW 3
#define L_SOCK_SEQPACKET 5
#define L_SOCK_NONBLOCK LINUX_O_NONBLOCK
#define L_SOCK_CLOEXEC LINUX_O_CLOEXEC

#define L_MSG_OOB 0x1
#define L_MSG_PEEK 0x2
#define L_MSG_DONTROUTE 0x4
#define L_MSG_CTRUNC 0x8
#define L_MSG_TRUNC 0x20
#define L_MSG_DONTWAIT 0x40
#define L_MSG_EOR 0x80
#define L_MSG_WAITALL 0x100
#define L_MSG_NOSIGNAL 0x4000
#define L_MSG_CMSG_CLOEXEC 0x40000000

#define L_SOL_SOCKET 1
#define L_SCM_RIGHTS 1
#define L_SCM_CREDENTIALS 2
#define L_SO_REUSEADDR 2
#define L_SO_TYPE 3
#define L_SO_ERROR 4
#define L_SO_BROADCAST 6
#define L_SO_SNDBUF 7
#define L_SO_RCVBUF 8
#define L_SO_KEEPALIVE 9
#define L_SO_OOBINLINE 10
#define L_SO_LINGER 13
#define L_SO_REUSEPORT 15
#define L_SO_PASSCRED 16
#define L_SO_PEERCRED 17
#define L_SO_RCVLOWAT 18
#define L_SO_SNDLOWAT 19
#define L_SO_RCVTIMEO 20
#define L_SO_SNDTIMEO 21
#define L_SO_ACCEPTCONN 30
#define L_SO_PEERSEC 31
#define L_SO_SNDBUFFORCE 32
#define L_SO_RCVBUFFORCE 33
#define L_SO_PROTOCOL 38
#define L_SO_DOMAIN 39

#define L_SCM_MAX_FD 253
#define UNIX_PATH_OFF 2
#define UNIX_ADDR_MAX 110  // sizeof(struct sockaddr_un) on Linux

struct linux_msghdr {
    void *name;
    uint32_t namelen, pad0;
    struct iovec *iov;
    uint64_t iovlen;
    void *control;
    uint64_t controllen;
    int32_t flags, pad1;
};
struct linux_mmsghdr { struct linux_msghdr hdr; uint32_t len, pad; };
struct linux_cmsghdr { uint64_t len; int32_t level, type; };
struct linux_ucred { int32_t pid; uint32_t uid, gid; };
#define LCMSG_ALIGN(n) (((n) + 7) & ~(size_t)7)

// ---- sockets -----------------------------------------------------------------------------
enum { S_NEW, S_LISTEN, S_CONNECTED };

typedef struct sock sock;
struct sock {
    int refs;
    pthread_mutex_t lock;
    int family, type, proto;
    int state;
    bool closed;          // its file is gone
    bool peer_gone;       // the connected peer's file is gone
    bool passcred;
    int pid;              // owner: SO_PEERCRED for those who connect to it
    int peer_pid;
    sock *peer;           // connected AF_UNIX peer (a reference)
    uint8_t name[UNIX_ADDR_MAX + 2]; uint32_t namelen;    // Linux sockaddr form; 0 = unnamed
    uint8_t pname[UNIX_ADDR_MAX + 2]; uint32_t pnamelen;
    int inbox_w;          // dgram, netlink: writing end of the inbox; the file's host fd reads it
    int notify_w;         // listener: one byte per queued connection; the host fd reads them
    sock *qhead, *qtail, *qnext;
    int nqueued, backlog;
    int conn_fd;          // a queued connection's host fd, until accept makes a file of it
    uint32_t nl_pid;
    struct regent *reg;   // its registry entry while bound
};

static const am_file_ops sock_ops;
static int sock_counter;

static sock *sock_new(int family, int type, int proto) {
    sock *s = calloc(1, sizeof *s);
    s->refs = 1;
    pthread_mutex_init(&s->lock, NULL);
    s->family = family;
    s->type = type;
    s->proto = proto;
    s->inbox_w = s->notify_w = s->conn_fd = -1;
    s->pid = am_self->proc->pid;
    return s;
}

static sock *sock_get(sock *s) { __atomic_add_fetch(&s->refs, 1, __ATOMIC_ACQ_REL); return s; }

static void sock_put(sock *s) {
    if (!s || __atomic_sub_fetch(&s->refs, 1, __ATOMIC_ACQ_REL)) return;
    if (s->inbox_w >= 0) close(s->inbox_w);
    if (s->notify_w >= 0) close(s->notify_w);
    if (s->conn_fd >= 0) close(s->conn_fd);
    sock_put(s->peer);
    pthread_mutex_destroy(&s->lock);
    free(s);
}

static sock *sock_of(int fd, long *err) {
    am_file *f = am_fd_get(fd);
    if (!f) { *err = AM_ERR(LINUX_EBADF); return NULL; }
    if (f->ops != &sock_ops) { *err = AM_ERR(LINUX_ENOTSOCK); return NULL; }
    *err = 0;
    return f->priv;
}

// Host sockets never raise SIGPIPE in this process; EPIPE comes back as an error instead.
static void host_sock_setup(int fd) {
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static long host_pair(int type, int sv[2]) {
    if (socketpair(AF_UNIX, type, 0, sv)) return am_errno(errno);
    host_sock_setup(sv[0]);
    host_sock_setup(sv[1]);
    if (type == SOCK_DGRAM) {
        // Darwin's default limit is 2 KiB a datagram; Linux allows far more.
        int sz = 1 << 20;
        setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
        setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    }
    return 0;
}

// Replaces f's host fd with `fd` in place, keeping its number and O_NONBLOCK.
static void swap_hostfd(am_file *f, int fd) {
    int fl = fcntl(f->hostfd, F_GETFL);
    dup2(fd, f->hostfd);
    close(fd);
    fcntl(f->hostfd, F_SETFD, FD_CLOEXEC);
    if (fl >= 0 && (fl & O_NONBLOCK)) fcntl(f->hostfd, F_SETFL, O_NONBLOCK);
    am_event_hostfd_changed(f);
}

static bool nonblocking(am_file *f, int lflags) {
    return (lflags & L_MSG_DONTWAIT) || (fcntl(f->hostfd, F_GETFL) & O_NONBLOCK);
}

static void wait_fd(int fd, short ev) {
    struct pollfd p = {fd, ev, 0};
    am_block_begin();
    while (poll(&p, 1, -1) < 0 && errno == EINTR) {}
    am_block_end();
}

bool am_sock_peer_gone(am_file *f) {
    if (f->ops != &sock_ops) return true;  // pipes and the like: EOF means the writer is gone
    sock *s = f->priv;
    return s->family == L_AF_UNIX ? s->peer_gone || s->closed : false;
}

// ---- in-flight fds -----------------------------------------------------------------------
typedef struct flight { struct flight *next; uint64_t id; int n; am_file *f[]; } flight;
static pthread_mutex_t flock_ = PTHREAD_MUTEX_INITIALIZER;
static flight *flights;
static uint64_t flight_ids;

// Parks n file references (taken over from the caller) and returns their id.
static uint64_t flight_put(am_file **f, int n) {
    flight *fl = malloc(sizeof *fl + n * sizeof *f);
    fl->n = n;
    memcpy(fl->f, f, n * sizeof *f);
    pthread_mutex_lock(&flock_);
    fl->id = ++flight_ids;
    fl->next = flights;
    flights = fl;
    pthread_mutex_unlock(&flock_);
    return fl->id;
}

// The files parked under id: taken out, or with peek new references to them left in place.
static int flight_take(uint64_t id, bool peek, am_file **out) {
    int n = 0;
    pthread_mutex_lock(&flock_);
    for (flight **pp = &flights; *pp; pp = &(*pp)->next) {
        flight *fl = *pp;
        if (fl->id != id) continue;
        n = fl->n;
        memcpy(out, fl->f, n * sizeof *out);
        if (peek) {
            for (int i = 0; i < n; i++) __atomic_add_fetch(&out[i]->refs, 1, __ATOMIC_ACQ_REL);
        } else {
            *pp = fl->next;
            free(fl);
        }
        break;
    }
    pthread_mutex_unlock(&flock_);
    return n;
}

static void flight_drop(uint64_t id) {
    am_file *f[L_SCM_MAX_FD];
    int n = id ? flight_take(id, false, f) : 0;
    for (int i = 0; i < n; i++) am_file_put(f[i]);
}

// ---- names -------------------------------------------------------------------------------
// Bound AF_UNIX sockets. Filesystem names are keyed by the inode of the socket file, so renames
// and other paths to it work as on Linux; abstract names by their bytes.
typedef struct regent {
    struct regent *next;
    bool abstract;
    dev_t dev; ino_t ino;
    uint8_t key[UNIX_ADDR_MAX]; size_t keylen;
    sock *s;
} regent;
static pthread_mutex_t reg_lock = PTHREAD_MUTEX_INITIALIZER;
static regent *names;

typedef struct {
    bool abstract;
    uint8_t key[UNIX_ADDR_MAX]; size_t keylen;  // abstract name bytes
    char path[UNIX_ADDR_MAX];                   // filesystem name
    uint8_t raw[UNIX_ADDR_MAX + 2]; uint32_t rawlen;  // as getsockname reports it
} uaddr;

static long uaddr_parse(const void *a, uint32_t len, uaddr *u) {
    if (len < UNIX_PATH_OFF || len > UNIX_ADDR_MAX) return AM_ERR(LINUX_EINVAL);
    const uint8_t *b = a;
    if ((b[0] | b[1] << 8) != L_AF_UNIX) return AM_ERR(LINUX_EINVAL);
    memset(u, 0, sizeof *u);
    size_t n = len - UNIX_PATH_OFF;
    if (n && b[UNIX_PATH_OFF] == 0) {
        u->abstract = true;
        u->keylen = n - 1;
        memcpy(u->key, b + UNIX_PATH_OFF + 1, n - 1);
        memcpy(u->raw, b, len);
        u->rawlen = len;
    } else {
        size_t pl = strnlen((const char *)b + UNIX_PATH_OFF, n);
        if (!pl || pl >= sizeof u->path) return AM_ERR(LINUX_EINVAL);
        memcpy(u->path, b + UNIX_PATH_OFF, pl);
        u->raw[0] = L_AF_UNIX;
        memcpy(u->raw + UNIX_PATH_OFF, u->path, pl + 1);
        u->rawlen = UNIX_PATH_OFF + pl + 1;
    }
    return 0;
}

// Finds the socket bound to u, with a reference.
static long name_lookup(const uaddr *u, sock **out) {
    dev_t dev = 0; ino_t ino = 0;
    if (!u->abstract) {
        char host[4096];
        long r = am_resolve(LINUX_AT_FDCWD, u->path, true, host, sizeof host, NULL, 0);
        if (r < 0) return r;
        struct stat st;
        if (stat(host, &st)) return am_errno(errno);
        dev = st.st_dev; ino = st.st_ino;
    }
    pthread_mutex_lock(&reg_lock);
    regent *e = names;
    for (; e; e = e->next) {
        if (e->abstract != u->abstract) continue;
        if (u->abstract ? e->keylen == u->keylen && !memcmp(e->key, u->key, u->keylen) : e->dev == dev && e->ino == ino)
            break;
    }
    if (e) *out = sock_get(e->s);
    pthread_mutex_unlock(&reg_lock);
    return e ? 0 : AM_ERR(LINUX_ECONNREFUSED);
}

static void name_unregister(sock *s) {
    pthread_mutex_lock(&reg_lock);
    for (regent **pp = &names; *pp; pp = &(*pp)->next)
        if (*pp == s->reg) { *pp = s->reg->next; free(s->reg); break; }
    s->reg = NULL;
    pthread_mutex_unlock(&reg_lock);
}

static long unix_bind(sock *s, const void *addr, uint32_t len) {
    uaddr u;
    if (len == UNIX_PATH_OFF) {
        // Autobind: a unique abstract name of five hex digits, as Linux makes them.
        static int seq;
        memset(&u, 0, sizeof u);
        u.abstract = true;
        u.keylen = 5;
        snprintf((char *)u.key, sizeof u.key, "%05x", __atomic_add_fetch(&seq, 1, __ATOMIC_RELAXED) & 0xFFFFF);
        u.raw[0] = L_AF_UNIX;
        memcpy(u.raw + UNIX_PATH_OFF + 1, u.key, 5);
        u.rawlen = UNIX_PATH_OFF + 1 + 5;
    } else {
        long r = uaddr_parse(addr, len, &u);
        if (r) return r;
    }
    if (s->namelen) return AM_ERR(LINUX_EINVAL);
    regent *e = calloc(1, sizeof *e);
    e->abstract = u.abstract;
    e->s = s;
    pthread_mutex_lock(&reg_lock);
    if (u.abstract) {
        for (regent *o = names; o; o = o->next)
            if (o->abstract && o->keylen == u.keylen && !memcmp(o->key, u.key, u.keylen)) {
                pthread_mutex_unlock(&reg_lock);
                free(e);
                return AM_ERR(LINUX_EADDRINUSE);
            }
        memcpy(e->key, u.key, u.keylen);
        e->keylen = u.keylen;
    } else {
        // The socket file the guest sees. A host socket file when the host path fits in a
        // sockaddr_un, else a plain file; either way the registry is what connect uses.
        char host[4096];
        long r = am_resolve(LINUX_AT_FDCWD, u.path, false, host, sizeof host, NULL, 0);
        struct stat st;
        if (r == 0 && lstat(host, &st) == 0) r = AM_ERR(LINUX_EADDRINUSE);
        if (r == 0) {
            struct sockaddr_un sun = {.sun_family = AF_UNIX};
            int hs = -1;
            if (strlen(host) < sizeof sun.sun_path && (hs = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0) {
                strcpy(sun.sun_path, host);
                if (bind(hs, (struct sockaddr *)&sun, sizeof sun)) r = am_errno(errno);
                close(hs);
            } else {
                int fd = open(host, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0777);
                if (fd < 0) r = am_errno(errno);
                else close(fd);
            }
            if (r == 0) chmod(host, 0777 & ~am_self->proc->umask);
            if (r == 0 && stat(host, &st)) r = am_errno(errno);
        }
        if (r) { pthread_mutex_unlock(&reg_lock); free(e); return r; }
        // A stale entry for a reused inode would shadow this one.
        for (regent **pp = &names; *pp;) {
            if (!(*pp)->abstract && (*pp)->dev == st.st_dev && (*pp)->ino == st.st_ino) {
                regent *o = *pp;
                *pp = o->next;
                o->s->reg = NULL;
                free(o);
            } else {
                pp = &(*pp)->next;
            }
        }
        e->dev = st.st_dev;
        e->ino = st.st_ino;
    }
    e->next = names;
    names = e;
    s->reg = e;
    memcpy(s->name, u.raw, u.rawlen);
    s->namelen = u.rawlen;
    pthread_mutex_unlock(&reg_lock);
    return 0;
}

// ---- release -----------------------------------------------------------------------------
// Fds still in flight towards a closing socket would never be received: read them out of its
// buffer and drop their references.
static void drain_flights(sock *s, int fd) {
    for (int guard = 0; guard < 4096; guard++) {
        if (s->type == L_SOCK_STREAM) {
            char buf[4096], cbuf[CMSG_SPACE(64 * sizeof(int))];
            struct iovec iov = {buf, sizeof buf};
            struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf};
            if (recvmsg(fd, &m, MSG_DONTWAIT) <= 0) return;
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
                if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
                int *t = (int *)CMSG_DATA(c);
                for (size_t i = 0; i < (c->cmsg_len - CMSG_LEN(0)) / sizeof(int); i++) {
                    uint64_t id = 0;
                    if (recv(t[i], &id, sizeof id, MSG_DONTWAIT) == sizeof id) flight_drop(id);
                    close(t[i]);
                }
            }
        } else {
            // Frame and datagram headers both start {len, pid, flight id}.
            uint32_t h[4];
            if (s->type == L_SOCK_SEQPACKET) {
                if (recv(fd, h, sizeof h, MSG_DONTWAIT) != sizeof h) return;
                char buf[4096];
                for (uint32_t left = h[0]; left;) {
                    ssize_t r = recv(fd, buf, left < sizeof buf ? left : sizeof buf, MSG_DONTWAIT);
                    if (r <= 0) break;
                    left -= r;
                }
            } else if (recv(fd, h, sizeof h, MSG_DONTWAIT) < 0) {
                return;
            }
            flight_drop((uint64_t)h[2] | (uint64_t)h[3] << 32);
        }
    }
}

static void sock_release(am_file *f) {
    sock *s = f->priv;
    if (s->reg) name_unregister(s);
    pthread_mutex_lock(&s->lock);
    s->closed = true;
    sock *peer = s->peer, *q = s->qhead;
    s->peer = NULL;
    s->qhead = s->qtail = NULL;
    pthread_mutex_unlock(&s->lock);
    if (peer) {
        peer->peer_gone = true;
        sock_put(peer);
    }
    // Connections nobody accepted: their clients see the close.
    while (q) {
        sock *n = q->qnext;
        if (q->peer) q->peer->peer_gone = true;
        q->closed = true;
        sock_put(q->peer);
        q->peer = NULL;
        sock_put(q);
        q = n;
    }
    if (s->family == L_AF_UNIX && s->state != S_LISTEN) drain_flights(s, f->hostfd);
    sock_put(s);
}

// ---- addresses ---------------------------------------------------------------------------
// Copies a Linux-form address out to the guest, as Linux does: truncated to its buffer, with
// the full length reported.
static void addr_out(void *dst, uint32_t *dlen, const void *src, uint32_t len) {
    if (!dst || !dlen) return;
    memcpy(dst, src, len < *dlen ? len : *dlen);
    *dlen = len;
}

// Linux sockaddr_in/in6 -> Darwin. Only the first two bytes differ (Darwin has sin_len).
static long inet_addr_in(int family, const void *a, uint32_t len, struct sockaddr_storage *h, socklen_t *hl) {
    if (len < 2) return AM_ERR(LINUX_EINVAL);
    uint16_t fam;
    memcpy(&fam, a, 2);
    memset(h, 0, sizeof *h);
    if (fam == L_AF_UNSPEC) {
        h->ss_family = AF_UNSPEC;
        h->ss_len = 2;
        *hl = 2;
        return 0;
    }
    if (fam == L_AF_INET) {
        if (len < 16) return AM_ERR(LINUX_EINVAL);
        memcpy((char *)h + 2, (const char *)a + 2, 14);
        h->ss_family = AF_INET;
        *hl = h->ss_len = sizeof(struct sockaddr_in);
        return 0;
    }
    if (fam == L_AF_INET6) {
        if (len < 24) return AM_ERR(LINUX_EINVAL);
        memcpy((char *)h + 2, (const char *)a + 2, (len < 28 ? len : 28) - 2);
        h->ss_family = AF_INET6;
        *hl = h->ss_len = sizeof(struct sockaddr_in6);
        return 0;
    }
    return AM_ERR(LINUX_EAFNOSUPPORT);
}

static uint32_t inet_addr_out(const struct sockaddr *h, uint8_t *out) {
    uint16_t fam;
    uint32_t n;
    switch (h->sa_family) {
    case AF_INET: fam = L_AF_INET; n = 16; break;
    case AF_INET6: fam = L_AF_INET6; n = 28; break;
    default: fam = L_AF_UNSPEC; n = 2; break;
    }
    memset(out, 0, n);
    if (n > 2) memcpy(out + 2, (const char *)h + 2, n - 2);
    memcpy(out, &fam, 2);
    return n;
}

// ---- control messages --------------------------------------------------------------------
typedef struct {
    am_file *files[L_SCM_MAX_FD];
    int nfiles;
    bool has_cred;
    int pid;
} ctl_in;

static void ctl_in_free(ctl_in *ci) {
    for (int i = 0; i < ci->nfiles; i++) am_file_put(ci->files[i]);
    ci->nfiles = 0;
}

static long ctl_parse(const struct linux_msghdr *m, ctl_in *ci) {
    ci->nfiles = 0;
    ci->has_cred = false;
    if (!m->control || m->controllen < sizeof(struct linux_cmsghdr)) return 0;
    const uint8_t *p = m->control, *end = p + m->controllen;
    while (p + sizeof(struct linux_cmsghdr) <= end) {
        const struct linux_cmsghdr *c = (const void *)p;
        if (c->len < sizeof *c || p + c->len > end) { ctl_in_free(ci); return AM_ERR(LINUX_EINVAL); }
        const uint8_t *d = p + sizeof *c;
        size_t dl = c->len - sizeof *c;
        if (c->level == L_SOL_SOCKET && c->type == L_SCM_RIGHTS) {
            for (size_t i = 0; i < dl / 4; i++) {
                int fd;
                memcpy(&fd, d + 4 * i, 4);
                am_file *f = am_fd_get(fd);
                if (!f || ci->nfiles == L_SCM_MAX_FD) {
                    ctl_in_free(ci);
                    return AM_ERR(f ? LINUX_EINVAL : LINUX_EBADF);
                }
                __atomic_add_fetch(&f->refs, 1, __ATOMIC_ACQ_REL);
                ci->files[ci->nfiles++] = f;
            }
        } else if (c->level == L_SOL_SOCKET && c->type == L_SCM_CREDENTIALS && dl >= sizeof(struct linux_ucred)) {
            struct linux_ucred u;
            memcpy(&u, d, sizeof u);
            ci->has_cred = true;
            ci->pid = u.pid;
        }
        p += LCMSG_ALIGN(c->len);
    }
    return 0;
}

// Builds the guest's control buffer on receive.
typedef struct { uint8_t *buf; size_t cap, len; int flags; } ctl_out;

static void ctl_put(ctl_out *co, int type, const void *data, size_t n) {
    size_t need = sizeof(struct linux_cmsghdr) + n;
    if (!co->buf || co->len + need > co->cap) { co->flags |= L_MSG_CTRUNC; return; }
    struct linux_cmsghdr h = {need, L_SOL_SOCKET, type};
    memcpy(co->buf + co->len, &h, sizeof h);
    memcpy(co->buf + co->len + sizeof h, data, n);
    co->len += LCMSG_ALIGN(need);
    if (co->len > co->cap) co->len = co->cap;
}

static void ctl_put_cred(ctl_out *co, int pid) {
    struct linux_ucred u = {pid, 0, 0};
    ctl_put(co, L_SCM_CREDENTIALS, &u, sizeof u);
}

// Installs received files as fds in this process and reports them; those that do not fit are
// closed, as on Linux.
static void ctl_put_files(ctl_out *co, am_file **f, int n, bool cloexec) {
    if (!n) return;
    size_t room = co->buf && co->cap > co->len + sizeof(struct linux_cmsghdr) ? co->cap - co->len - sizeof(struct linux_cmsghdr) : 0;
    int fit = (int)(room / sizeof(int)) < n ? (int)(room / sizeof(int)) : n;
    int fds[L_SCM_MAX_FD], k = 0;
    for (int i = 0; i < n; i++) {
        long fd = i < fit ? am_fd_install(am_self->proc, f[i], 0, cloexec) : -1;
        if (fd < 0) am_file_put(f[i]);
        else fds[k++] = (int)fd;
    }
    if (k < n) co->flags |= L_MSG_CTRUNC;
    if (k) {
        size_t need = sizeof(struct linux_cmsghdr) + k * sizeof(int);
        struct linux_cmsghdr h = {need, L_SOL_SOCKET, L_SCM_RIGHTS};
        memcpy(co->buf + co->len, &h, sizeof h);
        memcpy(co->buf + co->len + sizeof h, fds, k * sizeof(int));
        co->len += LCMSG_ALIGN(need);
        if (co->len > co->cap) co->len = co->cap;
    }
}

static int darwin_msg_flags(int l) {
    int d = 0;
    if (l & L_MSG_OOB) d |= MSG_OOB;
    if (l & L_MSG_PEEK) d |= MSG_PEEK;
    if (l & L_MSG_DONTROUTE) d |= MSG_DONTROUTE;
    if (l & L_MSG_DONTWAIT) d |= MSG_DONTWAIT;
    if (l & L_MSG_EOR) d |= MSG_EOR;
    if (l & L_MSG_WAITALL) d |= MSG_WAITALL;
    return d;
}

static int linux_msg_flags(int d) {
    int l = 0;
    if (d & MSG_OOB) l |= L_MSG_OOB;
    if (d & MSG_TRUNC) l |= L_MSG_TRUNC;
    if (d & MSG_CTRUNC) l |= L_MSG_CTRUNC;
    if (d & MSG_EOR) l |= L_MSG_EOR;
    return l;
}

static size_t iov_total(const struct iovec *iov, int n) {
    size_t t = 0;
    for (int i = 0; i < n; i++) t += iov[i].iov_len;
    return t;
}

// ---- framing (seqpacket, dgram, netlink) -------------------------------------------------
// Every message the runtime frames starts with this header. Datagrams also carry the sender's
// name; seqpacket frames are just the first 16 bytes.
typedef struct {
    uint32_t len;          // payload bytes
    int32_t pid;           // sender, for SCM_CREDENTIALS
    uint32_t flight_lo, flight_hi;
    uint32_t namelen;
    uint8_t name[UNIX_ADDR_MAX];
    uint8_t pad[2];
} dhdr;
_Static_assert(sizeof(dhdr) == 132, "dgram header");
#define FRAME_HDR 16

// recvmsg into [hdr][guest iovecs].
static ssize_t recv_hdr_iov(int fd, void *hdr, size_t hlen, const struct iovec *iov, int n, int dflags) {
    struct iovec v[n + 1];
    v[0] = (struct iovec){hdr, hlen};
    memcpy(v + 1, iov, n * sizeof *iov);
    struct msghdr m = {.msg_iov = v, .msg_iovlen = n + 1};
    return recvmsg(fd, &m, dflags);
}

// Receives exactly n bytes of a frame whose start has arrived; the sender is finishing it.
static long recv_rest(int fd, struct iovec *iov, int cnt) {
    size_t total = iov_total(iov, cnt), done = 0;
    while (done < total) {
        struct msghdr m = {.msg_iov = iov, .msg_iovlen = cnt};
        ssize_t r = recvmsg(fd, &m, 0);
        if (r < 0 && (errno == EAGAIN || errno == EINTR)) { wait_fd(fd, POLLIN); continue; }
        if (r <= 0) return r < 0 ? am_errno(errno) : AM_ERR(LINUX_EIO);
        done += r;
        while (cnt && (size_t)r >= iov->iov_len) { r -= iov->iov_len; iov++; cnt--; }
        if (cnt) { iov->iov_base = (char *)iov->iov_base + r; iov->iov_len -= r; }
    }
    return 0;
}

// Sends every byte; a nonblocking socket that fills mid-frame waits, since a frame cut short
// would corrupt the stream.
static long send_all(int fd, struct msghdr *m, int dflags) {
    size_t total = iov_total(m->msg_iov, m->msg_iovlen), done = 0;
    struct iovec v[m->msg_iovlen];
    memcpy(v, m->msg_iov, sizeof v);
    struct iovec *iov = v;
    int cnt = m->msg_iovlen;
    while (done < total) {
        struct msghdr mm = {.msg_iov = iov, .msg_iovlen = cnt};
        if (!done) { mm.msg_control = m->msg_control; mm.msg_controllen = m->msg_controllen; }
        ssize_t r = sendmsg(fd, &mm, done ? 0 : dflags);
        if (r < 0) {
            if (done && (errno == EAGAIN || errno == EINTR)) { wait_fd(fd, POLLOUT); continue; }
            return am_errno(errno);
        }
        done += r;
        while (cnt && (size_t)r >= iov->iov_len) { r -= iov->iov_len; iov++; cnt--; }
        if (cnt) { iov->iov_base = (char *)iov->iov_base + r; iov->iov_len -= r; }
    }
    return 0;
}

// ---- send --------------------------------------------------------------------------------
typedef struct {
    const struct iovec *iov;
    int iovcnt;
    int flags;               // Linux MSG_*
    const void *addr;
    uint32_t addrlen;
    ctl_in *ctl;
} sendargs;

static long send_inet(am_file *f, const sendargs *a) {
    struct sockaddr_storage h;
    socklen_t hl = 0;
    if (a->addr) {
        long r = inet_addr_in(((sock *)f->priv)->family, a->addr, a->addrlen, &h, &hl);
        if (r) return r;
    }
    struct msghdr m = {.msg_name = a->addr ? &h : NULL, .msg_namelen = hl, .msg_iov = (struct iovec *)a->iov,
                       .msg_iovlen = a->iovcnt};
    // Linux ping sockets fill in the ICMP checksum; Darwin drops a message without one.
    sock *s = f->priv;
    uint8_t *pkt = NULL;
    struct iovec pv;
    size_t len = iov_total(a->iov, a->iovcnt);
    if (s->family == L_AF_INET && s->type == L_SOCK_DGRAM && s->proto == IPPROTO_ICMP && len >= 8) {
        pkt = malloc(len + 1);
        size_t off = 0;
        for (int i = 0; i < a->iovcnt; i++) { memcpy(pkt + off, a->iov[i].iov_base, a->iov[i].iov_len); off += a->iov[i].iov_len; }
        pkt[len] = 0;
        pkt[2] = pkt[3] = 0;
        uint32_t sum = 0;
        for (size_t i = 0; i < len; i += 2) sum += (uint32_t)pkt[i] << 8 | pkt[i + 1];
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        pkt[2] = (uint8_t)(~sum >> 8);
        pkt[3] = (uint8_t)~sum;
        pv = (struct iovec){pkt, len};
        m.msg_iov = &pv;
        m.msg_iovlen = 1;
    }
    ssize_t r = sendmsg(f->hostfd, &m, darwin_msg_flags(a->flags));
    free(pkt);
    return r < 0 ? am_errno(errno) : r;
}

static long send_stream(am_file *f, sock *s, const sendargs *a) {
    if (s->state != S_CONNECTED) return AM_ERR(LINUX_ENOTCONN);
    struct msghdr m = {.msg_iov = (struct iovec *)a->iov, .msg_iovlen = a->iovcnt};
    char cbuf[CMSG_SPACE(sizeof(int))];
    int tag[2] = {-1, -1};
    uint64_t id = 0;
    if (a->ctl->nfiles) {
        // The tag: a socket holding the flight id, passed with host SCM_RIGHTS so that the
        // kernel delivers it with these bytes.
        if (!iov_total(a->iov, a->iovcnt)) return 0;
        long r = host_pair(SOCK_STREAM, tag);
        if (r) return r;
        id = flight_put(a->ctl->files, a->ctl->nfiles);
        a->ctl->nfiles = 0;
        (void)send(tag[1], &id, sizeof id, 0);
        close(tag[1]);
        m.msg_control = cbuf;
        m.msg_controllen = sizeof cbuf;
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &tag[0], sizeof(int));
    }
    ssize_t r = sendmsg(f->hostfd, &m, darwin_msg_flags(a->flags));
    long e = r < 0 ? am_errno(errno) : r;
    if (tag[0] >= 0) close(tag[0]);
    if (r < 0 && id) flight_drop(id);
    return e;
}

static long send_seqpacket(am_file *f, sock *s, const sendargs *a) {
    if (s->state != S_CONNECTED) return AM_ERR(LINUX_ENOTCONN);
    size_t len = iov_total(a->iov, a->iovcnt);
    uint64_t id = a->ctl->nfiles ? flight_put(a->ctl->files, a->ctl->nfiles) : 0;
    a->ctl->nfiles = 0;
    uint32_t h[4] = {(uint32_t)len, (uint32_t)(a->ctl->has_cred ? a->ctl->pid : am_self->proc->pid), (uint32_t)id,
                     (uint32_t)(id >> 32)};
    struct iovec v[a->iovcnt + 1];
    v[0] = (struct iovec){h, sizeof h};
    memcpy(v + 1, a->iov, a->iovcnt * sizeof *v);
    struct msghdr m = {.msg_iov = v, .msg_iovlen = a->iovcnt + 1};
    long r = send_all(f->hostfd, &m, (a->flags & L_MSG_DONTWAIT) ? MSG_DONTWAIT : 0);
    if (r) { flight_drop(id); return r; }
    return (long)len;
}

// Writes one framed datagram into the inbox of `to`.
static long deliver(am_file *f, sock *s, sock *to, const sendargs *a) {
    pthread_mutex_lock(&to->lock);
    bool dead = to->closed || to->inbox_w < 0;
    pthread_mutex_unlock(&to->lock);
    if (dead) return AM_ERR(LINUX_ECONNREFUSED);
    if (to->type != s->type) return AM_ERR(LINUX_EPROTOTYPE);
    size_t len = iov_total(a->iov, a->iovcnt);
    dhdr h = {.len = (uint32_t)len, .pid = a->ctl->has_cred ? a->ctl->pid : am_self->proc->pid};
    memcpy(h.name, s->name, s->namelen);
    h.namelen = s->namelen;
    uint64_t id = a->ctl->nfiles ? flight_put(a->ctl->files, a->ctl->nfiles) : 0;
    a->ctl->nfiles = 0;
    h.flight_lo = (uint32_t)id;
    h.flight_hi = (uint32_t)(id >> 32);
    struct iovec v[a->iovcnt + 1];
    v[0] = (struct iovec){&h, sizeof h};
    memcpy(v + 1, a->iov, a->iovcnt * sizeof *v);
    struct msghdr m = {.msg_iov = v, .msg_iovlen = a->iovcnt + 1};
    ssize_t r = sendmsg(to->inbox_w, &m, nonblocking(f, a->flags) ? MSG_DONTWAIT : 0);
    if (r < 0) {
        int e = errno;
        flight_drop(id);
        if (e == EPIPE || e == ENOTCONN || e == ECONNRESET) return AM_ERR(LINUX_ECONNREFUSED);
        if (e == ENOBUFS) return AM_ERR(LINUX_EAGAIN);
        return am_errno(e);
    }
    return (long)len;
}

static long send_dgram(am_file *f, sock *s, const sendargs *a) {
    sock *to;
    if (a->addr) {
        uaddr u;
        long r = uaddr_parse(a->addr, a->addrlen, &u);
        if (r) return r;
        if ((r = name_lookup(&u, &to))) return r;
    } else {
        pthread_mutex_lock(&s->lock);
        to = s->peer ? sock_get(s->peer) : NULL;
        pthread_mutex_unlock(&s->lock);
        if (!to) return AM_ERR(s->peer_gone ? LINUX_ECONNREFUSED : LINUX_ENOTCONN);
    }
    long r = deliver(f, s, to, a);
    sock_put(to);
    return r;
}

// Netlink: every dump request is answered by an empty dump; anything else by an error.
static long send_netlink(am_file *f, sock *s, const sendargs *a) {
    size_t len = iov_total(a->iov, a->iovcnt);
    uint8_t *buf = malloc(len ? len : 1);
    size_t off = 0;
    for (int i = 0; i < a->iovcnt; i++) { memcpy(buf + off, a->iov[i].iov_base, a->iov[i].iov_len); off += a->iov[i].iov_len; }
    for (off = 0; off + 16 <= len;) {
        uint32_t mlen, seq;
        uint16_t type, flags;
        memcpy(&mlen, buf + off, 4);
        memcpy(&type, buf + off + 4, 2);
        memcpy(&flags, buf + off + 6, 2);
        memcpy(&seq, buf + off + 8, 4);
        if (mlen < 16 || off + mlen > len) break;
        uint8_t reply[36];
        uint32_t rl;
        uint16_t rt, rf;
        int32_t err = 0;
        if ((flags & 0x300) == 0x300) {  // NLM_F_DUMP
            rl = 20; rt = 3; rf = 2;        // NLMSG_DONE, NLM_F_MULTI
        } else {
            rl = 36; rt = 2; rf = 0;        // NLMSG_ERROR
            err = (type & 3) == 2 ? -LINUX_ENODEV : -LINUX_EOPNOTSUPP;  // RTM_GET*: no such object
            memcpy(reply + 20, buf + off, 16);
        }
        memcpy(reply, &rl, 4);
        memcpy(reply + 4, &rt, 2);
        memcpy(reply + 6, &rf, 2);
        memcpy(reply + 8, &seq, 4);
        memcpy(reply + 12, &s->nl_pid, 4);
        memcpy(reply + 16, &err, 4);
        dhdr h = {.len = rl};
        struct iovec v[2] = {{&h, sizeof h}, {reply, rl}};
        struct msghdr m = {.msg_iov = v, .msg_iovlen = 2};
        (void)sendmsg(s->inbox_w, &m, MSG_DONTWAIT);
        off += (mlen + 3) & ~3u;
    }
    free(buf);
    return (long)len;
}

static long do_send(am_file *f, sendargs *a) {
    sock *s = f->priv;
    ctl_in none = {0};
    if (!a->ctl) a->ctl = &none;
    long r;
    switch (s->family == L_AF_UNIX ? s->type : -s->family) {
    case L_SOCK_STREAM: r = send_stream(f, s, a); break;
    case L_SOCK_SEQPACKET: r = send_seqpacket(f, s, a); break;
    case L_SOCK_DGRAM: r = send_dgram(f, s, a); break;
    case -L_AF_NETLINK: r = send_netlink(f, s, a); break;
    default: r = send_inet(f, a); break;
    }
    ctl_in_free(a->ctl);  // whatever was not handed on
    return r;
}

// ---- receive -----------------------------------------------------------------------------
typedef struct {
    const struct iovec *iov;
    int iovcnt;
    int flags;            // Linux MSG_* in
    int oflags;           // Linux MSG_* out
    void *addr;
    uint32_t *addrlen;
    ctl_out co;
} recvargs;

static long recv_inet(am_file *f, recvargs *a) {
    sock *s = f->priv;
    struct sockaddr_storage h;
    struct msghdr m = {.msg_name = &h, .msg_namelen = sizeof h, .msg_iov = (struct iovec *)a->iov, .msg_iovlen = a->iovcnt};
    // Darwin's ICMP datagram sockets hand over the IP header too; Linux ping sockets do not.
    bool icmp = s->family == L_AF_INET && s->type == L_SOCK_DGRAM && s->proto == IPPROTO_ICMP;
    size_t cap = iov_total(a->iov, a->iovcnt);
    uint8_t *pkt = NULL;
    struct iovec pv;
    if (icmp) {
        pv = (struct iovec){pkt = malloc(cap + 60), cap + 60};
        m.msg_iov = &pv;
        m.msg_iovlen = 1;
    }
    ssize_t r = recvmsg(f->hostfd, &m, darwin_msg_flags(a->flags));
    if (r < 0) { free(pkt); return am_errno(errno); }
    if (icmp) {
        size_t ihl = r > 0 ? (size_t)(pkt[0] & 0xF) * 4 : 0;
        r = (size_t)r > ihl ? r - (ssize_t)ihl : 0;
        size_t off = 0;
        for (int i = 0; i < a->iovcnt && off < (size_t)r; i++) {
            size_t n = a->iov[i].iov_len < (size_t)r - off ? a->iov[i].iov_len : (size_t)r - off;
            memcpy(a->iov[i].iov_base, pkt + ihl + off, n);
            off += n;
        }
        free(pkt);
    }
    a->oflags |= linux_msg_flags(m.msg_flags);
    if (a->addr && a->addrlen) {
        uint8_t out[28];
        if (m.msg_namelen) addr_out(a->addr, a->addrlen, out, inet_addr_out((struct sockaddr *)&h, out));
        else *a->addrlen = 0;
    }
    return r;
}

static long recv_stream(am_file *f, sock *s, recvargs *a) {
    if (s->state != S_CONNECTED) return AM_ERR(s->state == S_LISTEN ? LINUX_EINVAL : LINUX_ENOTCONN);
    char cbuf[CMSG_SPACE(64 * sizeof(int))];
    struct msghdr m = {.msg_iov = (struct iovec *)a->iov, .msg_iovlen = a->iovcnt};
    // Darwin does not hand out passed fds on a peek; neither do we then.
    if (!(a->flags & L_MSG_PEEK)) { m.msg_control = cbuf; m.msg_controllen = sizeof cbuf; }
    ssize_t r = recvmsg(f->hostfd, &m, darwin_msg_flags(a->flags));
    if (r < 0) return am_errno(errno);
    a->oflags |= linux_msg_flags(m.msg_flags) & ~L_MSG_CTRUNC;
    if (s->passcred) ctl_put_cred(&a->co, s->peer_pid);
    if (m.msg_controllen) {
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
            if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
            int *t = (int *)CMSG_DATA(c);
            for (size_t i = 0; i < (c->cmsg_len - CMSG_LEN(0)) / sizeof(int); i++) {
                uint64_t id = 0;
                if (recv(t[i], &id, sizeof id, MSG_DONTWAIT) == sizeof id) {
                    am_file *files[L_SCM_MAX_FD];
                    int n = flight_take(id, false, files);
                    ctl_put_files(&a->co, files, n, a->flags & L_MSG_CMSG_CLOEXEC);
                }
                close(t[i]);
            }
        }
    }
    if (a->addr && a->addrlen) addr_out(a->addr, a->addrlen, s->pname, s->pnamelen);
    return r;
}

static long recv_seqpacket(am_file *f, sock *s, recvargs *a) {
    if (s->state != S_CONNECTED) return AM_ERR(s->state == S_LISTEN ? LINUX_EINVAL : LINUX_ENOTCONN);
    int fd = f->hostfd;
    uint32_t h[4];
    // Wait for (or, nonblocking, check for) the start of a frame; EOF is the peer's close.
    ssize_t r = recv(fd, h, sizeof h, MSG_PEEK | (nonblocking(f, a->flags) ? MSG_DONTWAIT : 0));
    if (r < 0) return am_errno(errno);
    if (r == 0) return 0;
    size_t cap = iov_total(a->iov, a->iovcnt);
    bool peek = a->flags & L_MSG_PEEK;
    uint64_t id;
    if (peek) {
        // Peek until the whole frame (or as much as the guest wants) is there to look at.
        for (;;) {
            r = recv(fd, h, sizeof h, MSG_PEEK);
            if (r == sizeof h) {
                size_t want = h[0] < cap ? h[0] : cap;
                char *tmp = malloc(sizeof h + want);
                ssize_t got = recv(fd, tmp, sizeof h + want, MSG_PEEK);
                if (got == (ssize_t)(sizeof h + want)) {
                    size_t off = sizeof h;
                    for (int i = 0; i < a->iovcnt && off < sizeof h + want; i++) {
                        size_t n = a->iov[i].iov_len < sizeof h + want - off ? a->iov[i].iov_len : sizeof h + want - off;
                        memcpy(a->iov[i].iov_base, tmp + off, n);
                        off += n;
                    }
                    free(tmp);
                    break;
                }
                free(tmp);
            }
            if (r == 0) return 0;
            sched_yield();
        }
    } else {
        struct iovec hv = {h, sizeof h};
        long e = recv_rest(fd, &hv, 1);
        if (e) return e;
        size_t want = h[0] < cap ? h[0] : cap;
        struct iovec v[a->iovcnt];
        int n = 0;
        for (size_t left = want; n < a->iovcnt && left; n++) {
            v[n] = a->iov[n];
            if (v[n].iov_len > left) v[n].iov_len = left;
            left -= v[n].iov_len;
        }
        if ((e = recv_rest(fd, v, n))) return e;
        for (size_t left = h[0] - want; left;) {  // the part that does not fit is dropped
            char junk[4096];
            struct iovec jv = {junk, left < sizeof junk ? left : sizeof junk};
            if ((e = recv_rest(fd, &jv, 1))) return e;
            left -= jv.iov_len;
        }
    }
    if (h[0] > cap) a->oflags |= L_MSG_TRUNC;
    if (s->passcred) ctl_put_cred(&a->co, (int)h[1]);
    id = (uint64_t)h[2] | (uint64_t)h[3] << 32;
    if (id) {
        am_file *files[L_SCM_MAX_FD];
        int n = flight_take(id, peek, files);
        ctl_put_files(&a->co, files, n, a->flags & L_MSG_CMSG_CLOEXEC);
    }
    if (a->addr && a->addrlen) addr_out(a->addr, a->addrlen, s->pname, s->pnamelen);
    return (a->flags & L_MSG_TRUNC) ? (long)h[0] : (long)(h[0] < cap ? h[0] : cap);
}

static long recv_dgram(am_file *f, sock *s, recvargs *a) {
    dhdr h;
    int dfl = darwin_msg_flags(a->flags) & (MSG_PEEK | MSG_DONTWAIT);
    ssize_t r = recv_hdr_iov(f->hostfd, &h, sizeof h, a->iov, a->iovcnt, dfl);
    if (r < 0) return am_errno(errno);
    if ((size_t)r < sizeof h) return AM_ERR(LINUX_EIO);
    size_t got = r - sizeof h;
    if (h.len > got) a->oflags |= L_MSG_TRUNC;
    if (s->family == L_AF_NETLINK) {
        uint32_t nl[3] = {L_AF_NETLINK, 0, 0};  // from the kernel: pid 0, no groups
        if (a->addr && a->addrlen) addr_out(a->addr, a->addrlen, nl, 12);
    } else {
        if (s->passcred) ctl_put_cred(&a->co, h.pid);
        uint64_t id = (uint64_t)h.flight_lo | (uint64_t)h.flight_hi << 32;
        if (id) {
            am_file *files[L_SCM_MAX_FD];
            int n = flight_take(id, a->flags & L_MSG_PEEK, files);
            ctl_put_files(&a->co, files, n, a->flags & L_MSG_CMSG_CLOEXEC);
        }
        if (a->addr && a->addrlen) addr_out(a->addr, a->addrlen, h.name, h.namelen);
    }
    return (a->flags & L_MSG_TRUNC) ? (long)h.len : (long)got;
}

static long do_recv(am_file *f, recvargs *a) {
    sock *s = f->priv;
    switch (s->family == L_AF_UNIX ? s->type : -s->family) {
    case L_SOCK_STREAM: return recv_stream(f, s, a);
    case L_SOCK_SEQPACKET: return recv_seqpacket(f, s, a);
    case L_SOCK_DGRAM: case -L_AF_NETLINK: return recv_dgram(f, s, a);
    default: return recv_inet(f, a);
    }
}

// ---- file ops ----------------------------------------------------------------------------
static long sock_readv(am_file *f, const struct iovec *iov, int n) {
    recvargs a = {.iov = iov, .iovcnt = n};
    return do_recv(f, &a);
}

static long sock_writev(am_file *f, const struct iovec *iov, int n) {
    sendargs a = {.iov = iov, .iovcnt = n};
    return do_send(f, &a);
}

static long sock_read(am_file *f, void *buf, size_t n) {
    struct iovec v = {buf, n};
    return sock_readv(f, &v, 1);
}

static long sock_write(am_file *f, const void *buf, size_t n) {
    struct iovec v = {(void *)buf, n};
    return sock_writev(f, &v, 1);
}

static long sock_ioctl(am_file *f, unsigned long req, uint64_t arg) {
    sock *s = f->priv;
    switch (req) {
    case LINUX_FIONBIO: {
        int on = *(int *)arg;
        if (ioctl(f->hostfd, FIONBIO, &on)) return am_errno(errno);
        f->lflags = on ? f->lflags | LINUX_O_NONBLOCK : f->lflags & ~LINUX_O_NONBLOCK;
        return 0;
    }
    case LINUX_FIONREAD: {
        int n = 0;
        if (s->state == S_LISTEN) {
            n = 0;
        } else if (s->family == L_AF_UNIX && s->type == L_SOCK_SEQPACKET) {
            uint32_t h[4];
            if (recv(f->hostfd, h, sizeof h, MSG_PEEK | MSG_DONTWAIT) == sizeof h) n = (int)h[0];
        } else if (s->family == L_AF_NETLINK || (s->family == L_AF_UNIX && s->type == L_SOCK_DGRAM)) {
            dhdr h;
            if (recv(f->hostfd, &h, sizeof h, MSG_PEEK | MSG_DONTWAIT) == sizeof h) n = (int)h.len;
        } else if (ioctl(f->hostfd, FIONREAD, &n)) {
            return am_errno(errno);
        }
        *(int *)arg = n;
        return 0;
    }
    case 0x5411: *(int *)arg = 0; return 0;  // TIOCOUTQ / SIOCOUTQ
    }
    if ((req & 0xFF00) == 0x8900) return AM_ERR(LINUX_ENODEV);  // SIOCGIF*: no interfaces
    return AM_ERR(LINUX_ENOTTY);
}

static const am_file_ops sock_ops = {
    .name = "socket", .read = sock_read, .write = sock_write, .ioctl = sock_ioctl,
    .release = sock_release, .readv = sock_readv, .writev = sock_writev,
};

static long sock_install(sock *s, int hostfd, int flags, am_file **out) {
    char gp[32];
    snprintf(gp, sizeof gp, "socket:[%d]", __atomic_add_fetch(&sock_counter, 1, __ATOMIC_RELAXED) + 10000);
    am_file *f = am_file_new(hostfd, LINUX_O_RDWR, gp, &sock_ops, s);
    if (flags & L_SOCK_NONBLOCK) {
        fcntl(hostfd, F_SETFL, O_NONBLOCK);
        f->lflags |= LINUX_O_NONBLOCK;
    }
    long fd = am_fd_install(am_self->proc, f, 0, flags & L_SOCK_CLOEXEC);
    if (fd < 0) { am_file_put(f); return fd; }
    if (out) *out = f;
    return fd;
}

// ---- socket calls ------------------------------------------------------------------------
static long do_socket(int family, int type, int proto) {
    int flags = type & (L_SOCK_NONBLOCK | L_SOCK_CLOEXEC);
    type &= ~(L_SOCK_NONBLOCK | L_SOCK_CLOEXEC);
    int hfd = -1, inbox_w = -1;
    switch (family) {
    case L_AF_UNIX:
        if (proto) return AM_ERR(LINUX_EPROTONOSUPPORT);
        if (type == L_SOCK_STREAM || type == L_SOCK_SEQPACKET) {
            // Unconnected: a host socket that is not connected, until connect or listen.
            if ((hfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) return am_errno(errno);
            host_sock_setup(hfd);
        } else if (type == L_SOCK_DGRAM) {
            int sv[2];
            long r = host_pair(SOCK_DGRAM, sv);
            if (r) return r;
            hfd = sv[0];
            inbox_w = sv[1];
        } else {
            return AM_ERR(LINUX_EPROTOTYPE);
        }
        break;
    case L_AF_INET: case L_AF_INET6: {
        int ht = type == L_SOCK_STREAM ? SOCK_STREAM : type == L_SOCK_DGRAM ? SOCK_DGRAM : type == L_SOCK_RAW ? SOCK_RAW : -1;
        if (ht < 0) return AM_ERR(LINUX_EPROTOTYPE);
        if ((hfd = socket(family == L_AF_INET ? AF_INET : AF_INET6, ht, proto)) < 0) return am_errno(errno);
        host_sock_setup(hfd);
        break;
    }
    case L_AF_NETLINK: {
        if (type != L_SOCK_DGRAM && type != L_SOCK_RAW) return AM_ERR(LINUX_EPROTOTYPE);
        int sv[2];
        long r = host_pair(SOCK_DGRAM, sv);
        if (r) return r;
        hfd = sv[0];
        inbox_w = sv[1];
        break;
    }
    default:
        return AM_ERR(LINUX_EAFNOSUPPORT);
    }
    sock *s = sock_new(family, type, proto);
    s->inbox_w = inbox_w;
    return sock_install(s, hfd, flags, NULL);
}

static long do_socketpair(int family, int type, int proto, int *out) {
    int flags = type & (L_SOCK_NONBLOCK | L_SOCK_CLOEXEC);
    type &= ~(L_SOCK_NONBLOCK | L_SOCK_CLOEXEC);
    if (family != L_AF_UNIX) return AM_ERR(LINUX_EOPNOTSUPP);
    if (type != L_SOCK_STREAM && type != L_SOCK_SEQPACKET && type != L_SOCK_DGRAM) return AM_ERR(LINUX_EPROTOTYPE);
    if (proto) return AM_ERR(LINUX_EPROTONOSUPPORT);
    sock *s[2];
    int hfd[2];
    long r;
    if (type == L_SOCK_DGRAM) {
        int a[2], b[2];
        if ((r = host_pair(SOCK_DGRAM, a))) return r;
        if ((r = host_pair(SOCK_DGRAM, b))) { close(a[0]); close(a[1]); return r; }
        hfd[0] = a[0]; hfd[1] = b[0];
        for (int i = 0; i < 2; i++) s[i] = sock_new(family, type, 0);
        s[0]->inbox_w = a[1];
        s[1]->inbox_w = b[1];
    } else {
        if ((r = host_pair(SOCK_STREAM, hfd))) return r;
        for (int i = 0; i < 2; i++) s[i] = sock_new(family, type, 0);
    }
    for (int i = 0; i < 2; i++) {
        s[i]->state = S_CONNECTED;
        s[i]->peer = sock_get(s[!i]);
        s[i]->peer_pid = am_self->proc->pid;
    }
    long fd0 = sock_install(s[0], hfd[0], flags, NULL);
    if (fd0 < 0) { sock_put(s[1]); close(hfd[1]); return fd0; }
    long fd1 = sock_install(s[1], hfd[1], flags, NULL);
    if (fd1 < 0) {
        am_file *f = am_self->proc->fds[fd0];
        am_self->proc->fds[fd0] = NULL;
        am_file_put(f);
        return fd1;
    }
    out[0] = (int)fd0;
    out[1] = (int)fd1;
    return 0;
}

static long do_bind(int fd, const void *addr, uint32_t len) {
    long r;
    sock *s = sock_of(fd, &r);
    if (!s) return r;
    if (s->family == L_AF_UNIX) return unix_bind(s, addr, len);
    if (s->family == L_AF_NETLINK) {
        if (len < 12) return AM_ERR(LINUX_EINVAL);
        uint32_t pid;
        memcpy(&pid, (const char *)addr + 4, 4);
        s->nl_pid = pid ? pid : (uint32_t)am_self->proc->pid;
        return 0;
    }
    struct sockaddr_storage h;
    socklen_t hl;
    if ((r = inet_addr_in(s->family, addr, len, &h, &hl))) return r;
    return bind(am_fd_get(fd)->hostfd, (struct sockaddr *)&h, hl) ? am_errno(errno) : 0;
}

static long do_listen(int fd, int backlog) {
    long r;
    sock *s = sock_of(fd, &r);
    if (!s) return r;
    am_file *f = am_fd_get(fd);
    if (s->family != L_AF_UNIX) {
        if (s->family == L_AF_NETLINK) return AM_ERR(LINUX_EOPNOTSUPP);
        return listen(f->hostfd, backlog) ? am_errno(errno) : 0;
    }
    if (s->type == L_SOCK_DGRAM) return AM_ERR(LINUX_EOPNOTSUPP);
    pthread_mutex_lock(&s->lock);
    if (s->state == S_CONNECTED) { pthread_mutex_unlock(&s->lock); return AM_ERR(LINUX_EINVAL); }
    if (!s->namelen) { pthread_mutex_unlock(&s->lock); return AM_ERR(LINUX_EINVAL); }
    s->backlog = backlog < 16 ? 16 : backlog > 4096 ? 4096 : backlog;
    if (s->state == S_NEW) {
        int sv[2];
        if ((r = host_pair(SOCK_STREAM, sv))) { pthread_mutex_unlock(&s->lock); return r; }
        swap_hostfd(f, sv[0]);
        s->notify_w = sv[1];
        s->state = S_LISTEN;
        s->pid = am_self->proc->pid;
    }
    pthread_mutex_unlock(&s->lock);
    return 0;
}

static long unix_connect(am_file *f, sock *s, const void *addr, uint32_t len) {
    uaddr u;
    long r = uaddr_parse(addr, len, &u);
    if (r) return r;
    sock *to;
    if ((r = name_lookup(&u, &to))) return r;
    if (s->type == L_SOCK_DGRAM) {
        // A datagram socket just remembers its peer.
        if (to->type != L_SOCK_DGRAM) { sock_put(to); return AM_ERR(LINUX_EPROTOTYPE); }
        pthread_mutex_lock(&s->lock);
        sock *old = s->peer;
        s->peer = to;
        s->peer_gone = false;
        s->peer_pid = to->pid;
        memcpy(s->pname, to->name, to->namelen);
        s->pnamelen = to->namelen;
        pthread_mutex_unlock(&s->lock);
        sock_put(old);
        return 0;
    }
    if (s->state != S_NEW) { sock_put(to); return AM_ERR(s->state == S_CONNECTED ? LINUX_EISCONN : LINUX_EINVAL); }
    if (to->type != s->type) { sock_put(to); return AM_ERR(LINUX_EPROTOTYPE); }
    pthread_mutex_lock(&to->lock);
    if (to->state != S_LISTEN || to->closed) r = AM_ERR(LINUX_ECONNREFUSED);
    else if (to->nqueued >= to->backlog) r = AM_ERR(LINUX_EAGAIN);
    int sv[2];
    if (!r) r = host_pair(SOCK_STREAM, sv);
    if (r) { pthread_mutex_unlock(&to->lock); sock_put(to); return r; }
    // The server's end waits in the listener's queue until accept makes a file of it.
    sock *srv = sock_new(L_AF_UNIX, s->type, 0);
    srv->state = S_CONNECTED;
    srv->conn_fd = sv[1];
    srv->peer_pid = am_self->proc->pid;
    srv->pid = to->pid;
    memcpy(srv->name, to->name, to->namelen);
    srv->namelen = to->namelen;
    memcpy(srv->pname, s->name, s->namelen);
    srv->pnamelen = s->namelen;
    pthread_mutex_lock(&s->lock);
    swap_hostfd(f, sv[0]);
    s->state = S_CONNECTED;
    s->peer = sock_get(srv);
    srv->peer = sock_get(s);
    s->peer_pid = to->pid;
    memcpy(s->pname, to->name, to->namelen);
    s->pnamelen = to->namelen;
    pthread_mutex_unlock(&s->lock);
    if (to->qtail) to->qtail->qnext = srv;
    else to->qhead = srv;
    to->qtail = srv;
    to->nqueued++;
    (void)send(to->notify_w, "c", 1, MSG_DONTWAIT);
    pthread_mutex_unlock(&to->lock);
    sock_put(to);
    return 0;
}

static long do_connect(int fd, const void *addr, uint32_t len) {
    long r;
    sock *s = sock_of(fd, &r);
    if (!s) return r;
    am_file *f = am_fd_get(fd);
    if (s->family == L_AF_UNIX) return unix_connect(f, s, addr, len);
    if (s->family == L_AF_NETLINK) return 0;
    struct sockaddr_storage h;
    socklen_t hl;
    if ((r = inet_addr_in(s->family, addr, len, &h, &hl))) return r;
    return connect(f->hostfd, (struct sockaddr *)&h, hl) ? am_errno(errno) : 0;
}

static long do_accept(int fd, void *addr, uint32_t *alen, int flags) {
    long r;
    sock *s = sock_of(fd, &r);
    if (!s) return r;
    if (flags & ~(L_SOCK_NONBLOCK | L_SOCK_CLOEXEC)) return AM_ERR(LINUX_EINVAL);
    am_file *f = am_fd_get(fd);
    if (s->family != L_AF_UNIX) {
        if (s->family == L_AF_NETLINK) return AM_ERR(LINUX_EOPNOTSUPP);
        struct sockaddr_storage h;
        socklen_t hl = sizeof h;
        int nfd = accept(f->hostfd, (struct sockaddr *)&h, &hl);
        if (nfd < 0) return am_errno(errno);
        host_sock_setup(nfd);
        fcntl(nfd, F_SETFL, 0);  // BSD accept inherits O_NONBLOCK; Linux does not
        uint8_t out[28];
        if (addr && alen) addr_out(addr, alen, out, inet_addr_out((struct sockaddr *)&h, out));
        return sock_install(sock_new(s->family, s->type, s->proto), nfd, flags, NULL);
    }
    if (s->state != S_LISTEN) return AM_ERR(LINUX_EINVAL);
    for (;;) {
        // One byte per queued connection; blocking follows the listener's own O_NONBLOCK.
        char b;
        ssize_t n = recv(f->hostfd, &b, 1, 0);
        if (n < 0) return am_errno(errno);
        if (n == 0) return AM_ERR(LINUX_EINVAL);
        pthread_mutex_lock(&s->lock);
        sock *c = s->qhead;
        if (c) {
            s->qhead = c->qnext;
            if (!s->qhead) s->qtail = NULL;
            s->nqueued--;
            c->qnext = NULL;
        }
        pthread_mutex_unlock(&s->lock);
        if (!c) continue;
        int hfd = c->conn_fd;
        c->conn_fd = -1;
        if (addr && alen) {
            uint16_t fam = L_AF_UNIX;
            if (c->pnamelen) addr_out(addr, alen, c->pname, c->pnamelen);
            else addr_out(addr, alen, &fam, 2);
        }
        return sock_install(c, hfd, flags, NULL);
    }
}

static long do_getname(int fd, void *addr, uint32_t *alen, bool peer) {
    long r;
    sock *s = sock_of(fd, &r);
    if (!s) return r;
    if (s->family == L_AF_UNIX) {
        pthread_mutex_lock(&s->lock);
        uint8_t buf[UNIX_ADDR_MAX + 2] = {L_AF_UNIX};
        uint32_t n = 2;
        if (peer && s->state != S_CONNECTED && !s->peer) r = AM_ERR(LINUX_ENOTCONN);
        else if (peer ? s->pnamelen : s->namelen) {
            n = peer ? s->pnamelen : s->namelen;
            memcpy(buf, peer ? s->pname : s->name, n);
        }
        pthread_mutex_unlock(&s->lock);
        if (!r) addr_out(addr, alen, buf, n);
        return r;
    }
    if (s->family == L_AF_NETLINK) {
        uint32_t nl[3] = {L_AF_NETLINK, peer ? 0 : s->nl_pid, 0};
        addr_out(addr, alen, nl, 12);
        return 0;
    }
    struct sockaddr_storage h;
    socklen_t hl = sizeof h;
    int fdh = am_fd_get(fd)->hostfd;
    if ((peer ? getpeername : getsockname)(fdh, (struct sockaddr *)&h, &hl)) return am_errno(errno);
    uint8_t out[28];
    addr_out(addr, alen, out, inet_addr_out((struct sockaddr *)&h, out));
    return 0;
}

// Linux (level, option) -> Darwin, for options the host socket implements. 0 when unknown.
static bool host_opt(int level, int opt, int *hl, int *ho) {
    static const int sol[][2] = {
        {L_SO_REUSEADDR, SO_REUSEADDR}, {L_SO_TYPE, SO_TYPE}, {L_SO_ERROR, SO_ERROR},
        {L_SO_BROADCAST, SO_BROADCAST}, {L_SO_SNDBUF, SO_SNDBUF}, {L_SO_RCVBUF, SO_RCVBUF},
        {L_SO_SNDBUFFORCE, SO_SNDBUF}, {L_SO_RCVBUFFORCE, SO_RCVBUF},
        {L_SO_KEEPALIVE, SO_KEEPALIVE}, {L_SO_OOBINLINE, SO_OOBINLINE}, {L_SO_LINGER, SO_LINGER_SEC},
        {L_SO_REUSEPORT, SO_REUSEPORT}, {L_SO_RCVLOWAT, SO_RCVLOWAT}, {L_SO_SNDLOWAT, SO_SNDLOWAT},
        {L_SO_RCVTIMEO, SO_RCVTIMEO}, {L_SO_SNDTIMEO, SO_SNDTIMEO},
    };
    static const int tcp[][2] = {{1, TCP_NODELAY}, {4, TCP_KEEPALIVE}, {5, TCP_KEEPINTVL}, {6, TCP_KEEPCNT}};
    static const int ip[][2] = {{1, IP_TOS}, {2, IP_TTL}, {3, IP_HDRINCL}, {32, IP_MULTICAST_IF},
                                {33, IP_MULTICAST_TTL}, {34, IP_MULTICAST_LOOP}};
    static const int ip6[][2] = {{16, IPV6_UNICAST_HOPS}, {26, IPV6_V6ONLY}};
    const int (*t)[2];
    size_t n;
    switch (level) {
    case L_SOL_SOCKET: t = sol; n = sizeof sol / sizeof *sol; *hl = SOL_SOCKET; break;
    case 6: t = tcp; n = sizeof tcp / sizeof *tcp; *hl = IPPROTO_TCP; break;
    case 0: t = ip; n = sizeof ip / sizeof *ip; *hl = IPPROTO_IP; break;
    case 41: t = ip6; n = sizeof ip6 / sizeof *ip6; *hl = IPPROTO_IPV6; break;
    default: return false;
    }
    for (size_t i = 0; i < n; i++)
        if (t[i][0] == opt) { *ho = t[i][1]; return true; }
    return false;
}

static long put_int(void *val, uint32_t *len, int v) {
    if (!val || !len || *len < sizeof(int)) return AM_ERR(LINUX_EINVAL);
    memcpy(val, &v, sizeof v);
    *len = sizeof v;
    return 0;
}

static long do_getsockopt(int fd, int level, int opt, void *val, uint32_t *len) {
    long r;
    sock *s = sock_of(fd, &r);
    if (!s) return r;
    am_file *f = am_fd_get(fd);
    if (level == L_SOL_SOCKET) {
        switch (opt) {
        case L_SO_TYPE: return put_int(val, len, s->type);
        case L_SO_DOMAIN: return put_int(val, len, s->family);
        case L_SO_PROTOCOL: return put_int(val, len, s->proto);
        case L_SO_ACCEPTCONN: return put_int(val, len, s->state == S_LISTEN);
        case L_SO_PASSCRED: return put_int(val, len, s->passcred);
        case L_SO_PEERCRED: {
            if (!val || !len || *len < sizeof(struct linux_ucred)) return AM_ERR(LINUX_EINVAL);
            struct linux_ucred u = {s->family == L_AF_UNIX ? s->peer_pid : 0, 0, 0};
            if (s->family != L_AF_UNIX || (s->state != S_CONNECTED && !s->peer)) u = (struct linux_ucred){0, ~0u, ~0u};
            memcpy(val, &u, sizeof u);
            *len = sizeof u;
            return 0;
        }
        case L_SO_PEERSEC: {
            // The peer's SELinux label. There is one label for everything (see procfs.c);
            // init's property service refuses requests it cannot label.
            static const char label[] = "u:r:su:s0";
            if (s->family != L_AF_UNIX) return AM_ERR(LINUX_ENOPROTOOPT);
            if (!len) return AM_ERR(LINUX_EFAULT);
            if (*len < sizeof label) { *len = sizeof label; return AM_ERR(LINUX_ERANGE); }
            memcpy(val, label, sizeof label);
            *len = sizeof label;
            return 0;
        }
        case L_SO_ERROR:
            if (s->family == L_AF_UNIX || s->family == L_AF_NETLINK) return put_int(val, len, 0);
            break;
        }
    }
    int hl, ho;
    if (!host_opt(level, opt, &hl, &ho)) {
        if (level == L_SOL_SOCKET) return put_int(val, len, 0);
        return AM_ERR(LINUX_ENOPROTOOPT);
    }
    uint8_t buf[64];
    socklen_t bl = sizeof buf;
    if (getsockopt(f->hostfd, hl, ho, buf, &bl)) return am_errno(errno);
    if (level == L_SOL_SOCKET && opt == L_SO_ERROR) {
        int e;
        memcpy(&e, buf, sizeof e);
        return put_int(val, len, e ? (int)-am_errno(e) : 0);
    }
    if (!val || !len) return AM_ERR(LINUX_EINVAL);
    uint32_t n = bl < *len ? bl : *len;
    memcpy(val, buf, n);
    *len = bl;
    return 0;
}

static long do_setsockopt(int fd, int level, int opt, const void *val, uint32_t len) {
    long r;
    sock *s = sock_of(fd, &r);
    if (!s) return r;
    am_file *f = am_fd_get(fd);
    if (level == L_SOL_SOCKET && opt == L_SO_PASSCRED) {
        int v = 0;
        if (val && len >= sizeof v) memcpy(&v, val, sizeof v);
        s->passcred = v != 0;
        return 0;
    }
    int hl, ho;
    if (!host_opt(level, opt, &hl, &ho)) return 0;  // accepted and ignored, like most of Linux's
    if (s->family == L_AF_UNIX && level != L_SOL_SOCKET) return AM_ERR(LINUX_EOPNOTSUPP);
    if (setsockopt(f->hostfd, hl, ho, val, len)) {
        // Buffer sizes beyond the host's limits, and options our AF_UNIX sockets do not have,
        // are not worth failing over.
        if (s->family == L_AF_UNIX || ho == SO_SNDBUF || ho == SO_RCVBUF) return 0;
        return am_errno(errno);
    }
    return 0;
}

static long do_shutdown(int fd, int how) {
    long r;
    sock *s = sock_of(fd, &r);
    if (!s) return r;
    if (how < 0 || how > 2) return AM_ERR(LINUX_EINVAL);
    if (s->family == L_AF_UNIX && s->type == L_SOCK_DGRAM) return 0;
    if (s->family == L_AF_NETLINK) return 0;
    if (s->family == L_AF_UNIX && s->state != S_CONNECTED) return AM_ERR(LINUX_ENOTCONN);
    return shutdown(am_fd_get(fd)->hostfd, how) ? am_errno(errno) : 0;
}

static long do_sendmsg(int fd, const struct linux_msghdr *m, int flags) {
    long r;
    if (!sock_of(fd, &r)) return r;
    ctl_in *ci = malloc(sizeof *ci);
    if ((r = ctl_parse(m, ci))) { free(ci); return r; }
    sendargs a = {.iov = m->iov, .iovcnt = (int)m->iovlen, .flags = flags, .addr = m->namelen ? m->name : NULL,
                  .addrlen = m->namelen, .ctl = ci};
    r = do_send(am_fd_get(fd), &a);
    free(ci);
    return r;
}

static long do_recvmsg(int fd, struct linux_msghdr *m, int flags) {
    long r;
    if (!sock_of(fd, &r)) return r;
    recvargs a = {.iov = m->iov, .iovcnt = (int)m->iovlen, .flags = flags, .addr = m->name,
                  .addrlen = m->name ? &m->namelen : NULL, .co = {m->control, m->control ? m->controllen : 0, 0, 0}};
    if (!m->name) m->namelen = 0;
    r = do_recv(am_fd_get(fd), &a);
    if (r < 0) return r;
    m->controllen = a.co.len;
    m->flags = a.oflags | a.co.flags;
    return r;
}

long sys_net(am_ctx *c, long nr, bool *handled) {
#define A(i) (c->x[i])
    *handled = true;
    long r;
    switch (nr) {
    case LINUX_SYS_socket: return do_socket((int)A(0), (int)A(1), (int)A(2));
    case LINUX_SYS_socketpair: return do_socketpair((int)A(0), (int)A(1), (int)A(2), (int *)A(3));
    case LINUX_SYS_bind: return do_bind((int)A(0), (void *)A(1), (uint32_t)A(2));
    case LINUX_SYS_listen: return do_listen((int)A(0), (int)A(1));
    case LINUX_SYS_connect: return do_connect((int)A(0), (void *)A(1), (uint32_t)A(2));
    case LINUX_SYS_accept: return do_accept((int)A(0), (void *)A(1), (uint32_t *)A(2), 0);
    case LINUX_SYS_accept4: return do_accept((int)A(0), (void *)A(1), (uint32_t *)A(2), (int)A(3));
    case LINUX_SYS_getsockname: return do_getname((int)A(0), (void *)A(1), (uint32_t *)A(2), false);
    case LINUX_SYS_getpeername: return do_getname((int)A(0), (void *)A(1), (uint32_t *)A(2), true);
    case LINUX_SYS_getsockopt: return do_getsockopt((int)A(0), (int)A(1), (int)A(2), (void *)A(3), (uint32_t *)A(4));
    case LINUX_SYS_setsockopt: return do_setsockopt((int)A(0), (int)A(1), (int)A(2), (void *)A(3), (uint32_t)A(4));
    case LINUX_SYS_shutdown: return do_shutdown((int)A(0), (int)A(1));
    case LINUX_SYS_sendto: {
        if (!sock_of((int)A(0), &r)) return r;
        struct iovec v = {(void *)A(1), A(2)};
        sendargs a = {.iov = &v, .iovcnt = 1, .flags = (int)A(3), .addr = (void *)A(4), .addrlen = (uint32_t)A(5)};
        if (!a.addrlen) a.addr = NULL;
        return do_send(am_fd_get((int)A(0)), &a);
    }
    case LINUX_SYS_recvfrom: {
        if (!sock_of((int)A(0), &r)) return r;
        struct iovec v = {(void *)A(1), A(2)};
        recvargs a = {.iov = &v, .iovcnt = 1, .flags = (int)A(3), .addr = (void *)A(4), .addrlen = (uint32_t *)A(5)};
        return do_recv(am_fd_get((int)A(0)), &a);
    }
    case LINUX_SYS_sendmsg: return do_sendmsg((int)A(0), (void *)A(1), (int)A(2));
    case LINUX_SYS_recvmsg: return do_recvmsg((int)A(0), (void *)A(1), (int)A(2));
    case LINUX_SYS_sendmmsg: case LINUX_SYS_recvmmsg: {
        struct linux_mmsghdr *mm = (void *)A(1);
        unsigned n = (unsigned)A(2), i = 0;
        for (; i < n; i++) {
            r = nr == LINUX_SYS_sendmmsg ? do_sendmsg((int)A(0), &mm[i].hdr, (int)A(3))
                                         : do_recvmsg((int)A(0), &mm[i].hdr, (int)A(3) & ~0x10000);  // MSG_WAITFORONE
            if (r < 0) return i ? (long)i : r;
            mm[i].len = (uint32_t)r;
            if (nr == LINUX_SYS_recvmmsg && (A(3) & 0x10000)) A(3) |= L_MSG_DONTWAIT;
        }
        return i;
    }
    }
    *handled = false;
    return 0;
#undef A
}
