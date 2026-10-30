#include "lx.h"
// 16 client threads x 200 seqpacket messages (every 10th carries an fd) through one listener,
// served by 4 threads sharing one epoll set (EPOLLONESHOT, rearmed after each message);
// plus 8 threads hammering one eventfd.
#define CLIENTS 16
#define MSGS 200
static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL line %d: %s errno %d ", __LINE__, #c, errno); printf(__VA_ARGS__); printf("\n"); } } while (0)
static struct sockaddr_un addr;
static int addrlen, ep, lsock;
static int served, fdsrecv;

static void *client(void *arg) {
    long id = (long)arg;
    int c = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    int r;
    while ((r = connect(c, &addr, addrlen)) < 0 && errno == EAGAIN) usleep(1000);
    CHECK(r == 0, "connect %ld", id);
    for (int i = 0; i < MSGS; i++) {
        char msg[64];
        int n = snprintf(msg, sizeof msg, "client %ld msg %d", id, i);
        struct iovec iov = {msg, n};
        struct msghdr m = {0};
        m.msg_iov = &iov; m.msg_iovlen = 1;
        char cbuf[CMSG_SPACE(4)];
        int p[2] = {-1, -1};
        if (i % 10 == 0) {
            pipe(p);
            m.msg_control = cbuf; m.msg_controllen = sizeof cbuf;
            struct cmsghdr *cm = (void *)cbuf;
            cm->cmsg_len = CMSG_LEN(4); cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS;
            memcpy(CMSG_DATA(cm), &p[1], 4);
        }
        CHECK(sendmsg(c, &m, 0) == n, "send");
        if (p[1] >= 0) {
            close(p[1]);
            char b;
            CHECK(read(p[0], &b, 1) == 1 && b == 'k', "server wrote through passed fd");
            close(p[0]);
        }
        char reply[64];
        int k = read(c, reply, sizeof reply);
        CHECK(k == n && !memcmp(reply, msg, n), "echo %d %d", k, n);
    }
    close(c);
    return 0;
}

static void *server(void *arg) {
    struct epoll_event ev[4];
    for (;;) {
        int n = epoll_wait(ep, ev, 4, 2000);
        if (n == 0) return 0;  // idle: done
        for (int i = 0; i < n; i++) {
            int fd = (int)ev[i].data;
            if (fd == lsock) {
                int c;
                while ((c = accept4(lsock, 0, 0, SOCK_NONBLOCK)) >= 0) {
                    struct epoll_event e = {EPOLLIN | EPOLLONESHOT, (uint64_t)c};
                    epoll_ctl(ep, EPOLL_CTL_ADD, c, &e);
                }
                struct epoll_event e = {EPOLLIN | EPOLLONESHOT, (uint64_t)lsock};
                epoll_ctl(ep, EPOLL_CTL_MOD, lsock, &e);
                continue;
            }
            char buf[128], cbuf[64];
            struct iovec iov = {buf, sizeof buf};
            struct msghdr m = {0};
            m.msg_iov = &iov; m.msg_iovlen = 1; m.msg_control = cbuf; m.msg_controllen = sizeof cbuf;
            int k = recvmsg(fd, &m, MSG_CMSG_CLOEXEC);
            if (k == 0 || (ev[i].events & EPOLLHUP)) {
                epoll_ctl(ep, EPOLL_CTL_DEL, fd, 0);
                close(fd);
                continue;
            }
            if (k < 0) {
                CHECK(errno == EAGAIN, "recvmsg");
            } else {
                if (m.msg_controllen) {
                    int pf;
                    memcpy(&pf, CMSG_DATA((struct cmsghdr *)cbuf), 4);
                    CHECK(write(pf, "k", 1) == 1, "write passed");
                    close(pf);
                    __atomic_add_fetch(&fdsrecv, 1, __ATOMIC_RELAXED);
                }
                CHECK(write(fd, buf, k) == k, "echo write");
                __atomic_add_fetch(&served, 1, __ATOMIC_RELAXED);
            }
            struct epoll_event e = {EPOLLIN | EPOLLONESHOT, (uint64_t)fd};
            epoll_ctl(ep, EPOLL_CTL_MOD, fd, &e);
        }
    }
}

static int efd;
static uint64_t etotal;
static int estop, edone;
static void *eproducer(void *a) { for (int i = 0; i < 5000; i++) { uint64_t v = 1; write(efd, &v, 8); } return 0; }
static void *econsumer(void *a) {
    for (;;) {
        uint64_t v;
        if (read(efd, &v, 8) != 8) break;
        if (__atomic_load_n(&estop, __ATOMIC_ACQUIRE)) { __atomic_add_fetch(&edone, 1, __ATOMIC_RELAXED); break; }
        __atomic_add_fetch(&etotal, v, __ATOMIC_RELAXED);
    }
    return 0;
}

int main(void) {
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path + 1, "stress");
    addrlen = 2 + 1 + 6;
    lsock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
    CHECK(bind(lsock, &addr, addrlen) == 0, "bind");
    CHECK(listen(lsock, 64) == 0, "listen");
    ep = epoll_create1(0);
    struct epoll_event e = {EPOLLIN | EPOLLONESHOT, (uint64_t)lsock};
    epoll_ctl(ep, EPOLL_CTL_ADD, lsock, &e);
    pthread_t s[4], c[CLIENTS];
    for (int i = 0; i < 4; i++) pthread_create(&s[i], 0, server, 0);
    for (long i = 0; i < CLIENTS; i++) pthread_create(&c[i], 0, client, (void *)i);
    for (int i = 0; i < CLIENTS; i++) pthread_join(c[i], 0);
    for (int i = 0; i < 4; i++) pthread_join(s[i], 0);
    printf("served %d messages, %d fds passed\n", served, fdsrecv);
    CHECK(served == CLIENTS * MSGS && fdsrecv == CLIENTS * MSGS / 10, "totals");

    efd = eventfd(0, 0);
    pthread_t p[4], q[4];
    for (int i = 0; i < 4; i++) pthread_create(&q[i], 0, econsumer, 0);
    for (int i = 0; i < 4; i++) pthread_create(&p[i], 0, eproducer, 0);
    for (int i = 0; i < 4; i++) pthread_join(p[i], 0);
    while (__atomic_load_n(&etotal, __ATOMIC_RELAXED) < 20000) usleep(1000);
    __atomic_store_n(&estop, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&edone, __ATOMIC_RELAXED) < 4) { uint64_t v = 1; write(efd, &v, 8); usleep(2000); }
    for (int i = 0; i < 4; i++) pthread_join(q[i], 0);
    printf("eventfd total %lu\n", etotal);
    CHECK(etotal == 20000, "eventfd total");
    printf("%s\n", fails ? "STRESS FAILED" : "stress ok");
    return fails != 0;
}
