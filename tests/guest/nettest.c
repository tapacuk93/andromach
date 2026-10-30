// Sockets, epoll, eventfd, timerfd, memfd, select and netlink, from inside a guest.
#include "lx.h"

static int fails, passes;
#define CHECK(cond, ...) do { if (cond) passes++; else { fails++; printf("FAIL %s:%d: %s (errno %d) ", __FILE__, __LINE__, #cond, errno); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int send_fds(int s, const void *buf, size_t n, int *fds, int nfds) {
    char cbuf[CMSG_SPACE(4 * 8)];
    struct iovec iov = {(void *)buf, n};
    struct msghdr m = {0};
    m.msg_iov = &iov; m.msg_iovlen = 1;
    if (nfds) {
        m.msg_control = cbuf; m.msg_controllen = CMSG_SPACE(4 * nfds);
        struct cmsghdr *c = (void *)cbuf;
        c->cmsg_len = CMSG_LEN(4 * nfds); c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(c), fds, 4 * nfds);
    }
    return sendmsg(s, &m, MSG_NOSIGNAL);
}

// Receives into buf; returns bytes, fills fds (count in *nfds), pid of SCM_CREDENTIALS in *pid.
static int recv_fds(int s, void *buf, size_t n, int *fds, int *nfds, int *pid, int flags, int *mflags) {
    char cbuf[256];
    struct iovec iov = {buf, n};
    struct msghdr m = {0};
    m.msg_iov = &iov; m.msg_iovlen = 1; m.msg_control = cbuf; m.msg_controllen = sizeof cbuf;
    int r = recvmsg(s, &m, flags);
    *nfds = 0;
    if (pid) *pid = -1;
    if (mflags) *mflags = m.msg_flags;
    if (r < 0) return r;
    for (char *p = cbuf; p + sizeof(struct cmsghdr) <= cbuf + m.msg_controllen;) {
        struct cmsghdr *c = (void *)p;
        if (c->cmsg_type == SCM_RIGHTS) {
            int k = (c->cmsg_len - sizeof *c) / 4;
            memcpy(fds, CMSG_DATA(c), 4 * k);
            *nfds = k;
        } else if (c->cmsg_type == SCM_CREDENTIALS && pid) {
            *pid = ((struct ucred *)CMSG_DATA(c))->pid;
        }
        p += CMSG_ALIGN(c->cmsg_len);
    }
    return r;
}

static void test_stream_pair(void) {
    int sv[2], p[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    CHECK(write(sv[0], "hello", 5) == 5, "write");
    char b[64] = {0};
    CHECK(read(sv[1], b, sizeof b) == 5 && !memcmp(b, "hello", 5), "read %s", b);
    // pass a pipe's write end, then write through the received fd
    CHECK(pipe(p) == 0, "pipe");
    CHECK(send_fds(sv[0], "F", 1, &p[1], 1) == 1, "send fds");
    close(p[1]);
    int fds[8], n, pid;
    CHECK(recv_fds(sv[1], b, sizeof b, fds, &n, &pid, 0, 0) == 1 && n == 1, "recv fds n=%d", n);
    if (n == 1) {
        CHECK(write(fds[0], "via", 3) == 3, "write passed fd");
        close(fds[0]);
        CHECK(read(p[0], b, 3) == 3 && !memcmp(b, "via", 3), "read via pipe");
        CHECK(read(p[0], b, 3) == 0, "pipe EOF once the passed fd is closed");
    }
    close(p[0]);
    struct ucred cr; uint32_t l = sizeof cr;
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &cr, &l) == 0 && cr.pid == getpid() && cr.uid == 0, "peercred %d", cr.pid);
    int t; l = 4;
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &t, &l) == 0 && t == SOCK_STREAM, "SO_TYPE %d", t);
    close(sv[0]);
    CHECK(read(sv[1], b, sizeof b) == 0, "EOF after peer close");
    CHECK(write(sv[1], "x", 1) < 0 && errno == EPIPE, "EPIPE after peer close");
    close(sv[1]);
    printf("stream pair done\n");
}

static void test_seqpacket_pair(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0, "socketpair seqpacket");
    CHECK(write(sv[0], "one", 3) == 3, "w1");
    CHECK(write(sv[0], "twotwo", 6) == 6, "w2");
    CHECK(write(sv[0], "", 0) == 0, "w3 empty");
    struct iovec v[2] = {{"ab", 2}, {"cde", 3}};
    CHECK(writev(sv[0], v, 2) == 5, "writev");
    char b[64] = {0};
    CHECK(recv(sv[1], b, sizeof b, MSG_PEEK) == 3, "peek");
    CHECK(read(sv[1], b, sizeof b) == 3 && !memcmp(b, "one", 3), "r1");
    int fl;
    CHECK(recv_fds(sv[1], b, 3, (int[8]){0}, &fl, 0, 0, &fl) == 3, "r2 truncated");
    CHECK(fl & MSG_TRUNC, "MSG_TRUNC flag %x", fl);
    CHECK(read(sv[1], b, sizeof b) == 0, "r3 empty message");
    CHECK(read(sv[1], b, sizeof b) == 5 && !memcmp(b, "abcde", 5), "r4 writev was one message");
    // epoll: HUP on peer close
    int ep = epoll_create1(0);
    struct epoll_event ev = {EPOLLIN | EPOLLRDHUP, 42}, out[4];
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, sv[1], &ev) == 0, "epoll add");
    CHECK(epoll_wait(ep, out, 4, 0) == 0, "nothing ready");
    close(sv[0]);
    int n = epoll_wait(ep, out, 4, 100);
    CHECK(n == 1 && out[0].data == 42 && (out[0].events & EPOLLHUP) && (out[0].events & EPOLLIN), "HUP n=%d ev=%x", n, n > 0 ? out[0].events : 0);
    CHECK(read(sv[1], b, sizeof b) == 0, "seqpacket EOF");
    close(sv[1]);
    close(ep);
    printf("seqpacket pair done\n");
}

static void test_dgram_pair(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0, "socketpair dgram");
    struct iovec v[3] = {{"x", 1}, {"yy", 2}, {"zzz", 3}};
    CHECK(writev(sv[0], v, 3) == 6, "writev");
    static char big[60000];
    big[59999] = 7;
    CHECK(send(sv[0], big, sizeof big, 0) == sizeof big, "big datagram");
    char b[64];
    CHECK(read(sv[1], b, sizeof b) == 6 && !memcmp(b, "xyyzzz", 6), "one datagram");
    static char big2[60000];
    CHECK(recv(sv[1], big2, sizeof big2, 0) == sizeof big2 && big2[59999] == 7, "big recv");
    CHECK(recv(sv[1], b, sizeof b, MSG_DONTWAIT) < 0 && errno == EAGAIN, "EAGAIN");
    close(sv[0]); close(sv[1]);
    printf("dgram pair done\n");
}

struct srvarg { const char *path; int abstract; int type; int ready; };

static int mkaddr(struct sockaddr_un *a, const char *name, int abstract) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    if (abstract) { strcpy(a->sun_path + 1, name); return 2 + 1 + strlen(name); }
    strcpy(a->sun_path, name);
    return 2 + strlen(name) + 1;
}

static void *client(void *arg) {
    struct srvarg *sa = arg;
    while (!__atomic_load_n(&sa->ready, __ATOMIC_ACQUIRE)) usleep(1000);
    int c = socket(AF_UNIX, sa->type, 0);
    struct sockaddr_un a;
    int al = mkaddr(&a, sa->path, sa->abstract);
    if (connect(c, &a, al)) { printf("connect: errno %d\n", errno); return 0; }
    write(c, "ping", 4);
    char b[16];
    int n = read(c, b, sizeof b);
    if (n != 4 || memcmp(b, "pong", 4)) printf("client: bad reply %d\n", n);
    close(c);
    return 0;
}

static void test_listen(const char *name, int abstract, int type) {
    struct srvarg sa = {name, abstract, type, 0};
    int s = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
    struct sockaddr_un a;
    int al = mkaddr(&a, name, abstract);
    if (!abstract) unlink(name);
    CHECK(bind(s, &a, al) == 0, "bind %s", name);
    int s2 = socket(AF_UNIX, type, 0);
    CHECK(bind(s2, &a, al) < 0 && errno == EADDRINUSE, "second bind EADDRINUSE");
    close(s2);
    CHECK(listen(s, 8) == 0, "listen");
    pthread_t th;
    pthread_create(&th, 0, client, &sa);
    int ep = epoll_create1(0);
    struct epoll_event ev = {EPOLLIN, 7}, out[2];
    epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev);
    __atomic_store_n(&sa.ready, 1, __ATOMIC_RELEASE);
    CHECK(epoll_wait(ep, out, 2, 2000) == 1 && out[0].data == 7, "listener readable");
    struct sockaddr_un pa; uint32_t pl = sizeof pa;
    int c = accept4(s, &pa, &pl, SOCK_CLOEXEC);
    CHECK(c >= 0, "accept");
    char b[16];
    CHECK(read(c, b, sizeof b) == 4 && !memcmp(b, "ping", 4), "server read");
    struct ucred cr; uint32_t l = sizeof cr;
    CHECK(getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &l) == 0 && cr.pid == getpid(), "peercred");
    struct sockaddr_un na; uint32_t nl = sizeof na;
    CHECK(getsockname(c, &na, &nl) == 0 && nl == (uint32_t)al && !memcmp(&na, &a, al), "getsockname on accepted nl=%u al=%d", nl, al);
    CHECK(write(c, "pong", 4) == 4, "server write");
    pthread_join(th, 0);
    CHECK(read(c, b, sizeof b) == 0, "EOF after client close");
    close(c); close(s); close(ep);
    if (!abstract) {
        int c2 = socket(AF_UNIX, type, 0);
        CHECK(connect(c2, &a, al) < 0 && errno == ECONNREFUSED, "connect to closed listener refused (errno %d)", errno);
        close(c2);
        unlink(name);
        c2 = socket(AF_UNIX, type, 0);
        CHECK(connect(c2, &a, al) < 0 && errno == ENOENT, "connect to removed path ENOENT");
        close(c2);
    }
    printf("listen %s type %d done\n", name, type);
}

static void test_dgram_named(void) {
    const char *path = "/data/local/tmp/dg.sock";
    unlink(path);
    int r = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un a;
    int al = mkaddr(&a, path, 0);
    CHECK(bind(r, &a, al) == 0, "bind dgram");
    int one = 1;
    CHECK(setsockopt(r, SOL_SOCKET, SO_PASSCRED, &one, 4) == 0, "passcred");
    int w = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_un wa;
    int wal = mkaddr(&wa, "dgsender", 1);
    CHECK(bind(w, &wa, wal) == 0, "bind sender abstract");
    CHECK(sendto(w, "log1", 4, 0, &a, al) == 4, "sendto");
    int p[2]; pipe(p);
    // connected send with an fd
    CHECK(connect(w, &a, al) == 0, "connect dgram");
    CHECK(send_fds(w, "log2", 4, &p[0], 1) == 4, "send with fd");
    char b[64];
    struct sockaddr_un from; uint32_t fl = sizeof from;
    CHECK(recvfrom(r, b, sizeof b, 0, &from, &fl) == 4 && !memcmp(b, "log1", 4), "recvfrom");
    CHECK(fl == (uint32_t)wal && !memcmp(&from, &wa, wal), "sender address fl=%u", fl);
    int fds[8], n, pid;
    CHECK(recv_fds(r, b, sizeof b, fds, &n, &pid, 0, 0) == 4 && n == 1 && pid == getpid(), "fd + creds n=%d pid=%d", n, pid);
    if (n == 1) {
        write(p[1], "q", 1);
        CHECK(read(fds[0], b, 1) == 1 && b[0] == 'q', "received pipe read end works");
        close(fds[0]);
    }
    close(p[0]); close(p[1]);
    close(r);
    CHECK(send(w, "x", 1, 0) < 0 && errno == ECONNREFUSED, "send to closed ECONNREFUSED errno=%d", errno);
    close(w);
    unlink(path);
    printf("dgram named done\n");
}

static void test_fd_lifetime(void) {
    // A socket passed over a socket and closed by the sender stays alive in the receiver.
    int sv[2], q[2];
    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
    socketpair(AF_UNIX, SOCK_STREAM, 0, q);
    CHECK(send_fds(sv[0], "s", 1, &q[0], 1) == 1, "send socket");
    close(q[0]);
    char b[8]; int fds[8], n;
    CHECK(recv_fds(sv[1], b, sizeof b, fds, &n, 0, MSG_CMSG_CLOEXEC, 0) == 1 && n == 1, "recv socket");
    if (n == 1) {
        CHECK(write(fds[0], "abc", 3) == 3, "write to passed socket");
        CHECK(read(q[1], b, 3) == 3 && !memcmp(b, "abc", 3), "peer reads");
        close(fds[0]);
        CHECK(read(q[1], b, 3) == 0, "EOF once the last reference closes");
    }
    // Unreceived in-flight fds are released when the receiving socket closes.
    int p[2]; pipe(p);
    CHECK(send_fds(sv[0], "t", 1, &p[1], 1) == 1, "send pipe");
    close(p[1]);
    close(sv[1]);
    CHECK(read(p[0], b, 1) == 0, "pipe writer released with the unread message");
    close(p[0]); close(sv[0]); close(q[1]);
    printf("fd lifetime done\n");
}

static void test_eventfd(void) {
    int e = eventfd(0, EFD_NONBLOCK);
    uint64_t v;
    CHECK(read(e, &v, 8) < 0 && errno == EAGAIN, "empty EAGAIN");
    v = 3; write(e, &v, 8);
    v = 4; write(e, &v, 8);
    struct pollfd p = {e, POLLIN, 0};
    CHECK(poll(&p, 1, 0) == 1, "poll readable");
    CHECK(read(e, &v, 8) == 8 && v == 7, "sum %lu", v);
    CHECK(poll(&p, 1, 0) == 0, "not readable after read");
    close(e);
    e = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);
    CHECK(read(e, &v, 8) == 8 && v == 1, "sem 1");
    CHECK(read(e, &v, 8) == 8 && v == 1, "sem 2");
    CHECK(read(e, &v, 8) < 0 && errno == EAGAIN, "sem empty");
    close(e);
    printf("eventfd done\n");
}

static long ms_since(struct timespec *t0) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) * 1000 + (t.tv_nsec - t0->tv_nsec) / 1000000;
}

static void test_timerfd(void) {
    int t = timerfd_create(CLOCK_MONOTONIC, 0);
    CHECK(t >= 0, "timerfd_create");
    struct itimerspec its = {{0, 10000000}, {0, 20000000}}, cur;
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    CHECK(timerfd_settime(t, 0, &its, 0) == 0, "settime");
    CHECK(timerfd_gettime(t, &cur) == 0 && cur.it_value.tv_nsec > 0 && cur.it_interval.tv_nsec == 10000000, "gettime");
    uint64_t n;
    // Counts are checked against measured time: a loaded machine oversleeps.
    CHECK(read(t, &n, 8) == 8, "first read");
    long ms = ms_since(&t0);
    CHECK(ms >= 19 && (long)n >= 1 && (long)n <= 2 + (ms - 20) / 10, "first expiry after %ld ms, count %lu", ms, n);
    usleep(55000);
    CHECK(read(t, &n, 8) == 8, "second read");
    long ms2 = ms_since(&t0);
    long due = (ms2 - 20) / 10 + 1, before = (ms - 20) / 10 + 1;
    CHECK((long)n >= due - before - 1 && (long)n <= due - before + 1, "periodic count %lu, expected about %ld", n, due - before);
    // through epoll
    int ep = epoll_create1(0);
    struct epoll_event ev = {EPOLLIN, 99}, out[2];
    epoll_ctl(ep, EPOLL_CTL_ADD, t, &ev);
    CHECK(epoll_wait(ep, out, 2, 1000) == 1 && out[0].data == 99, "timer via epoll");
    // disarm
    struct itimerspec zero = {{0, 0}, {0, 0}};
    timerfd_settime(t, 0, &zero, 0);
    CHECK(epoll_wait(ep, out, 2, 30) == 0, "disarmed: quiet");
    // absolute, nonblocking, realtime
    close(t);
    t = timerfd_create(CLOCK_REALTIME, 04000);
    CHECK(read(t, &n, 8) < 0 && errno == EAGAIN, "nonblocking EAGAIN");
    struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
    now.tv_nsec += 15000000; if (now.tv_nsec >= 1000000000) { now.tv_sec++; now.tv_nsec -= 1000000000; }
    struct itimerspec abs = {{0, 0}, now};
    timerfd_settime(t, TFD_TIMER_ABSTIME, &abs, 0);
    struct pollfd p = {t, POLLIN, 0};
    CHECK(poll(&p, 1, 1000) == 1, "abs realtime fires");
    CHECK(read(t, &n, 8) == 8 && n == 1, "abs count");
    close(t); close(ep);
    printf("timerfd done\n");
}

static void test_epoll_modes(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    int ep = epoll_create1(0);
    struct epoll_event ev = {EPOLLIN | EPOLLET, 1}, out[4];
    epoll_ctl(ep, EPOLL_CTL_ADD, sv[1], &ev);
    write(sv[0], "a", 1);
    CHECK(epoll_wait(ep, out, 4, 100) == 1, "ET first");
    CHECK(epoll_wait(ep, out, 4, 0) == 0, "ET not again");
    write(sv[0], "b", 1);
    CHECK(epoll_wait(ep, out, 4, 100) == 1, "ET new data");
    ev.events = EPOLLIN; ev.data = 2;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, sv[1], &ev) == 0, "MOD");
    CHECK(epoll_wait(ep, out, 4, 0) == 1 && out[0].data == 2, "LT reports");
    CHECK(epoll_wait(ep, out, 4, 0) == 1, "LT again");
    ev.events = EPOLLIN | EPOLLONESHOT; ev.data = 3;
    epoll_ctl(ep, EPOLL_CTL_MOD, sv[1], &ev);
    CHECK(epoll_wait(ep, out, 4, 0) == 1 && out[0].data == 3, "oneshot");
    CHECK(epoll_wait(ep, out, 4, 0) == 0, "oneshot disabled");
    epoll_ctl(ep, EPOLL_CTL_MOD, sv[1], &ev);
    CHECK(epoll_wait(ep, out, 4, 0) == 1, "oneshot rearmed");
    ev.events = EPOLLIN | EPOLLOUT; ev.data = 4;
    epoll_ctl(ep, EPOLL_CTL_MOD, sv[1], &ev);
    int n = epoll_wait(ep, out, 4, 0);
    CHECK(n == 1 && out[0].events == (EPOLLIN | EPOLLOUT), "merged in+out n=%d ev=%x", n, out[0].events);
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, sv[1], &ev) < 0 && errno == 17, "EEXIST");
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, sv[1], 0) == 0, "DEL");
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, sv[1], 0) < 0 && errno == ENOENT, "DEL ENOENT");
    // closing a registered fd drops it; the number can be reused and added again
    epoll_ctl(ep, EPOLL_CTL_ADD, sv[1], &ev);
    int num = sv[1];
    close(sv[1]);
    int e = eventfd(1, 0);
    CHECK(e == num, "fd number reused %d %d", e, num);
    ev.data = 5;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, e, &ev) == 0, "re-add reused number");
    CHECK(epoll_wait(ep, out, 4, 0) == 1 && out[0].data == 5, "only the new file");
    // nested epoll
    int outer = epoll_create1(0);
    struct epoll_event oe = {EPOLLIN, 77};
    CHECK(epoll_ctl(outer, EPOLL_CTL_ADD, ep, &oe) == 0, "nest");
    CHECK(epoll_wait(outer, out, 4, 100) == 1 && out[0].data == 77, "nested ready");
    close(outer); close(e); close(sv[0]); close(ep);
    printf("epoll modes done\n");
}

static void *delayed_write(void *arg) { usleep(30000); write(*(int *)arg, "z", 1); return 0; }

static void test_select(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    fd_set r; memset(&r, 0, sizeof r);
    r.fds_bits[sv[1] / 64] |= 1ul << (sv[1] % 64);
    struct timeval tv = {0, 0};
    CHECK(select(sv[1] + 1, &r, 0, 0, &tv) == 0, "select empty");
    pthread_t th; pthread_create(&th, 0, delayed_write, &sv[0]);
    memset(&r, 0, sizeof r);
    r.fds_bits[sv[1] / 64] |= 1ul << (sv[1] % 64);
    tv.tv_sec = 2;
    CHECK(select(sv[1] + 1, &r, 0, 0, &tv) == 1 && (r.fds_bits[sv[1] / 64] & (1ul << (sv[1] % 64))), "select wakes");
    pthread_join(th, 0);
    close(sv[0]); close(sv[1]);
    printf("select done\n");
}

static void test_memfd(void) {
    int m = memfd_create("test", 3);
    CHECK(m >= 0, "memfd_create");
    CHECK(ftruncate(m, 16384) == 0, "ftruncate");
    char *a = mmap(0, 16384, PROT_READ | PROT_WRITE, MAP_SHARED, m, 0);
    char *b = mmap(0, 16384, PROT_READ | PROT_WRITE, MAP_SHARED, m, 0);
    CHECK(a != (void *)-1 && b != (void *)-1 && a != b, "mmap twice");
    strcpy(a, "shared!");
    CHECK(!strcmp(b, "shared!"), "visible through the other mapping");
    CHECK(fcntl(m, F_ADD_SEALS, 8) == 0, "F_ADD_SEALS");
    munmap(a, 16384); munmap(b, 16384); close(m);
    int s = signalfd(-1, &(uint64_t){1ul << 9}, 04000);
    char buf[128];
    CHECK(s >= 0 && read(s, buf, sizeof buf) < 0 && errno == EAGAIN, "signalfd quiet");
    close(s);
    int in = inotify_init1(04000);
    CHECK(in >= 0 && inotify_add_watch(in, "/data", 0x100) >= 1, "inotify");
    CHECK(read(in, buf, sizeof buf) < 0 && errno == EAGAIN, "inotify quiet");
    close(in);
    printf("memfd/signalfd/inotify done\n");
}

static void test_netlink(void) {
    struct ifaddrs *ifa = (void *)1;
    int r = getifaddrs(&ifa);
    CHECK(r == 0, "getifaddrs r=%d", r);
    if (r == 0) { CHECK(ifa == 0, "no interfaces"); freeifaddrs(ifa); }
    CHECK(if_nametoindex("lo") == 0, "if_nametoindex");
    printf("netlink done\n");
}

struct inetarg { int port; };
static void *inet_client(void *arg) {
    struct inetarg *ia = arg;
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {AF_INET, htons(ia->port), htonl(0x7f000001)};
    if (connect(c, &a, sizeof a)) { printf("inet connect errno %d\n", errno); return 0; }
    send(c, "tcp!", 4, 0);
    char b[8]; recv(c, b, sizeof b, 0);
    close(c);
    return 0;
}

static void test_inet(void) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    CHECK(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, 4) == 0, "reuseaddr");
    struct sockaddr_in a = {AF_INET, 0, htonl(0x7f000001)};
    CHECK(bind(s, &a, sizeof a) == 0, "inet bind");
    uint32_t l = sizeof a;
    CHECK(getsockname(s, &a, &l) == 0 && a.sin_family == AF_INET && a.sin_port, "getsockname port %d", htons(a.sin_port));
    CHECK(listen(s, 4) == 0, "inet listen");
    struct inetarg ia = {htons(a.sin_port)};
    pthread_t th; pthread_create(&th, 0, inet_client, &ia);
    struct sockaddr_in pa; l = sizeof pa;
    int c = accept4(s, &pa, &l, SOCK_NONBLOCK);
    CHECK(c >= 0 && pa.sin_family == AF_INET && pa.sin_addr == htonl(0x7f000001), "accept4 fam=%d", pa.sin_family);
    CHECK(fcntl(c, F_GETFL) & O_NONBLOCK, "SOCK_NONBLOCK on accepted");
    struct pollfd p = {c, POLLIN, 0};
    poll(&p, 1, 2000);
    char b[8];
    CHECK(recv(c, b, sizeof b, 0) == 4 && !memcmp(b, "tcp!", 4), "inet recv");
    send(c, "ok", 2, 0);
    pthread_join(th, 0);
    int e; l = 4;
    CHECK(getsockopt(c, SOL_SOCKET, SO_ERROR, &e, &l) == 0 && e == 0, "SO_ERROR");
    close(c); close(s);
    printf("inet done\n");
}

int main(int argc, char **argv) {
    mkdir("/data/local/tmp/a-rather-long-directory-name-to-exceed-the-host-sun-path-limit-of-104-bytes", 0755);
    test_stream_pair();
    test_seqpacket_pair();
    test_dgram_pair();
    test_listen("abstract-seq", 1, SOCK_SEQPACKET);
    test_listen("/data/local/tmp/stream.sock", 0, SOCK_STREAM);
    test_listen("/data/local/tmp/a-rather-long-directory-name-to-exceed-the-host-sun-path-limit-of-104-bytes/s", 0, SOCK_SEQPACKET);
    test_dgram_named();
    test_fd_lifetime();
    test_eventfd();
    test_timerfd();
    test_epoll_modes();
    test_select();
    test_memfd();
    test_netlink();
    test_inet();
    printf("%d passed, %d failed\n", passes, fails);
    return fails != 0;
}
