// Host-side test of the binder driver (runtime/binder.c). Fake guest processes and threads (am_proc,
// am_thread) open /dev/binder through the runtime's own open path and talk the protocol libbinder
// and servicemanager use, with hand-built buffers in the exact UAPI layouts.
//
// Part A runs every process step by step from one host thread with nonblocking reads, switching
// am_self, so each step's results can be checked exactly. Part B runs real pthreads with blocking
// reads: a context manager, a service with a spawned looper, concurrent clients, then the death
// of the service while calls and a death notification are pending.
#include "../runtime/am.h"
#include "../runtime/linux.h"
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__thread am_thread *am_self;
const char *am_root = "/nonexistent";
const char *am_datadir;
int am_strace;
bool am_deny_exec;
long am_errno(int e) { return -(long)e; }

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); abort(); } } while (0)

// ---- fake guests -------------------------------------------------------------------------
typedef struct gproc { am_proc proc; am_file *f; int fd; uint64_t map; } gproc;

static void gproc_init(gproc *g, int pid) {
    memset(g, 0, sizeof *g);
    pthread_mutex_init(&g->proc.lock, NULL);
    g->proc.pid = g->proc.ppid = pid;
    strcpy(g->proc.cwd, "/");
}

static am_thread *mkthread(gproc *g, int tid) {
    am_thread *t = calloc(1, sizeof *t);
    t->proc = &g->proc;
    t->tid = tid;
    return t;
}

static long bioctl(gproc *g, am_thread *t, unsigned long req, void *arg) {
    am_self = t;
    return g->f->ops->ioctl(g->f, req, (uint64_t)arg);
}

static void gopen(gproc *g, am_thread *t, const char *dev, bool nonblock) {
    am_self = t;
    am_file *f;
    CHECK(am_open(dev, LINUX_AT_FDCWD, LINUX_O_RDWR | LINUX_O_CLOEXEC | (nonblock ? LINUX_O_NONBLOCK : 0), 0, &f) == 0);
    CHECK(f->ops && !strcmp(f->ops->name, "binder"));
    g->f = f;
    g->fd = am_fd_install(&g->proc, f, 3, true);
    long m = f->ops->mmap(f, 0, 1 << 20, LINUX_PROT_READ, LINUX_MAP_PRIVATE, 0);
    CHECK(m > 0);
    g->map = m;
    CHECK(f->ops->mmap(f, 0, 1 << 20, LINUX_PROT_READ | LINUX_PROT_WRITE, LINUX_MAP_PRIVATE, 0) == -LINUX_EPERM);
    struct binder_version v = {0};
    CHECK(bioctl(g, t, BINDER_VERSION, &v) == 0 && v.protocol_version == 8);
    uint32_t max = 0;
    CHECK(bioctl(g, t, BINDER_SET_MAX_THREADS, &max) == 0);
}

// Closes the guest's binder fd: the last reference, so the driver releases the process.
static void gclose(gproc *g, am_thread *t) {
    am_self = t;
    pthread_mutex_lock(&g->proc.lock);
    am_file *f = g->proc.fds[g->fd];
    g->proc.fds[g->fd] = NULL;
    pthread_mutex_unlock(&g->proc.lock);
    am_file_put(f);
    g->f = NULL;
}

static bool readable(gproc *g) {
    struct pollfd p = {g->f->hostfd, POLLIN, 0};
    return poll(&p, 1, 0) == 1;
}

// ---- protocol helpers --------------------------------------------------------------------
typedef struct { uint8_t b[2048]; size_t n; } cmdbuf;

static void put(cmdbuf *w, const void *p, size_t n) { memcpy(w->b + w->n, p, n); w->n += n; }
static void put32(cmdbuf *w, uint32_t v) { put(w, &v, 4); }
static void put64(cmdbuf *w, uint64_t v) { put(w, &v, 8); }
static void cmd32(cmdbuf *w, uint32_t cmd, uint32_t v) { put32(w, cmd); put32(w, v); }
static void cmd64(cmdbuf *w, uint32_t cmd, uint64_t v) { put32(w, cmd); put64(w, v); }

static void txn(cmdbuf *w, uint32_t cmd, uint32_t handle, uint32_t code, uint32_t flags,
                const void *data, size_t dsz, const uint64_t *offs, size_t noffs, uint64_t sg) {
    struct binder_transaction_data_sg tr = {0};
    tr.transaction_data.target.handle = handle;
    tr.transaction_data.code = code;
    tr.transaction_data.flags = flags | TF_ACCEPT_FDS;
    tr.transaction_data.data_size = dsz;
    tr.transaction_data.offsets_size = noffs * 8;
    tr.transaction_data.data.ptr.buffer = (uint64_t)data;
    tr.transaction_data.data.ptr.offsets = (uint64_t)offs;
    tr.buffers_size = sg;
    put32(w, cmd);
    put(w, &tr, (cmd == BC_TRANSACTION_SG || cmd == BC_REPLY_SG) ? sizeof tr : sizeof tr.transaction_data);
}

typedef struct ev {
    uint32_t cmd;
    struct binder_transaction_data_secctx tr;   // BR_TRANSACTION(_SEC_CTX), BR_REPLY
    struct binder_ptr_cookie pc;                // BR_INCREFS ...
    uint64_t cookie;                            // BR_DEAD_BINDER, BR_CLEAR_DEATH_NOTIFICATION_DONE
} ev;

static int parse(const uint8_t *b, size_t n, ev *out, int max) {
    int k = 0;
    size_t i = 0;
    while (i < n) {
        CHECK(k < max);
        ev *e = &out[k++];
        memset(e, 0, sizeof *e);
        memcpy(&e->cmd, b + i, 4);
        i += 4;
        size_t sz = LINUX_IOC_SIZE(e->cmd);
        switch (e->cmd) {
        case BR_TRANSACTION: case BR_REPLY: case BR_TRANSACTION_SEC_CTX: memcpy(&e->tr, b + i, sz); break;
        case BR_INCREFS: case BR_ACQUIRE: case BR_RELEASE: case BR_DECREFS: memcpy(&e->pc, b + i, sz); break;
        case BR_DEAD_BINDER: case BR_CLEAR_DEATH_NOTIFICATION_DONE: memcpy(&e->cookie, b + i, 8); break;
        case BR_NOOP: case BR_TRANSACTION_COMPLETE: case BR_DEAD_REPLY: case BR_FAILED_REPLY: case BR_SPAWN_LOOPER: break;
        default: fprintf(stderr, "unexpected return %#x\n", e->cmd); CHECK(0);
        }
        i += sz;
    }
    return k;
}

// One BINDER_WRITE_READ: writes w (if any), reads up to `rsize` bytes. Returns the number of
// returns parsed, or the negative error.
static int wr(gproc *g, am_thread *t, cmdbuf *w, ev *evs, int max, size_t rsize) {
    uint8_t rb[4096];
    struct binder_write_read bwr = {0};
    if (w) { bwr.write_buffer = (uint64_t)w->b; bwr.write_size = w->n; }
    bwr.read_buffer = (uint64_t)rb;
    bwr.read_size = rsize;
    long r = bioctl(g, t, BINDER_WRITE_READ, &bwr);
    if (w) { CHECK(r < 0 || bwr.write_consumed == w->n); w->n = 0; }
    if (r < 0) { CHECK(bwr.read_consumed == 0); return (int)r; }
    return parse(rb, bwr.read_consumed, evs, max);
}

// Checks the returns are exactly the commands listed (0-terminated).
static void expect(const ev *evs, int n, ...) {
    va_list ap;
    va_start(ap, n);
    int i = 0;
    for (uint32_t c; (c = va_arg(ap, uint32_t)); i++) {
        if (i >= n || evs[i].cmd != c) {
            fprintf(stderr, "return %d: want %#x, got %#x (%d returns)\n", i, c, i < n ? evs[i].cmd : 0, n);
            CHECK(0);
        }
    }
    va_end(ap);
    if (i != n) { fprintf(stderr, "%d returns, expected %d (next %#x)\n", n, i, evs[i].cmd); CHECK(0); }
}

static const ev *find(const ev *evs, int n, uint32_t cmd) {
    for (int i = 0; i < n; i++) if (evs[i].cmd == cmd) return &evs[i];
    return NULL;
}

static struct flat_binder_object binder_obj(uint64_t ptr, uint64_t cookie) {
    return (struct flat_binder_object){.type = BINDER_TYPE_BINDER, .flags = FLAT_BINDER_FLAG_ACCEPTS_FDS | 0x7f,
                                       .binder = ptr, .cookie = cookie};
}

static struct flat_binder_object handle_obj(uint32_t h) {
    return (struct flat_binder_object){.type = BINDER_TYPE_HANDLE, .handle = h};
}

static const void *bufp(const ev *e) { return (const void *)e->tr.transaction_data.data.ptr.buffer; }
static const uint64_t *offp(const ev *e) { return (const uint64_t *)e->tr.transaction_data.data.ptr.offsets; }

static bool in_map(gproc *g, uint64_t a) { return a >= g->map && a < g->map + (1 << 20); }

enum { ADD = 3, GET = 1, ECHO = 10, HANG = 11, PING = 12 };

// ---- part A: step by step ----------------------------------------------------------------
static void part_a(void) {
    static gproc sm, s, c, h;
    gproc_init(&sm, 100); gproc_init(&s, 200); gproc_init(&c, 300); gproc_init(&h, 400);
    am_thread *sm1 = mkthread(&sm, 100), *s1 = mkthread(&s, 200), *s2 = mkthread(&s, 201);
    am_thread *c1 = mkthread(&c, 300), *c2 = mkthread(&c, 302), *h1 = mkthread(&h, 400);
    ev e[32];
    int n;
    cmdbuf w = {0};

    gopen(&sm, sm1, "/dev/binder", true);
    gopen(&s, s1, "/dev/binder", true);
    gopen(&c, c1, "/dev/binder", true);
    gopen(&h, h1, "/dev/hwbinder", true);

    // Context manager, as servicemanager does it.
    struct flat_binder_object mgr = {.type = BINDER_TYPE_BINDER,
                                     .flags = FLAT_BINDER_FLAG_TXN_SECURITY_CTX | FLAT_BINDER_FLAG_ACCEPTS_FDS};
    CHECK(bioctl(&sm, sm1, BINDER_SET_CONTEXT_MGR_EXT, &mgr) == 0);
    CHECK(bioctl(&s, s1, BINDER_SET_CONTEXT_MGR, &(int){0}) == -LINUX_EBUSY);
    uint32_t one = 1;
    CHECK(bioctl(&sm, sm1, BINDER_ENABLE_ONEWAY_SPAM_DETECTION, &one) == 0);
    put32(&w, BC_ENTER_LOOPER);
    CHECK(wr(&sm, sm1, &w, e, 32, 256) == -LINUX_EAGAIN);
    CHECK(!readable(&sm));

    // The service registers itself: BR_INCREFS/BR_ACQUIRE for its new node come before the
    // transaction completes.
    struct { char name[8]; struct flat_binder_object obj; } add = {"svc", binder_obj(0xB0, 0xC0)};
    uint64_t add_offs[] = {8};
    txn(&w, BC_TRANSACTION, 0, ADD, 0, &add, sizeof add, add_offs, 1, 0);
    n = wr(&s, s1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_INCREFS, BR_ACQUIRE, BR_TRANSACTION_COMPLETE, 0);
    CHECK(e[1].pc.ptr == 0xB0 && e[1].pc.cookie == 0xC0 && e[2].pc.ptr == 0xB0);
    struct binder_ptr_cookie pc = {0xB0, 0xC0};
    put32(&w, BC_INCREFS_DONE); put(&w, &pc, sizeof pc);
    put32(&w, BC_ACQUIRE_DONE); put(&w, &pc, sizeof pc);
    CHECK(wr(&s, s1, &w, e, 32, 0) == 0);

    CHECK(readable(&sm));
    n = wr(&sm, sm1, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_SEC_CTX, 0);
    struct binder_transaction_data *td = &e[1].tr.transaction_data;
    CHECK(td->code == ADD && td->sender_pid == 200 && td->sender_euid == 0 && td->target.ptr == 0);
    CHECK(td->data_size == sizeof add && td->offsets_size == 8);
    CHECK(in_map(&sm, td->data.ptr.buffer) && in_map(&sm, e[1].tr.secctx));
    CHECK(!strcmp((const char *)e[1].tr.secctx, "u:r:su:s0"));
    CHECK(offp(&e[1])[0] == 8);
    const struct flat_binder_object *got = (const void *)((const char *)bufp(&e[1]) + 8);
    CHECK(!strcmp(bufp(&e[1]), "svc"));
    CHECK(got->type == BINDER_TYPE_HANDLE && got->handle == 1 && got->cookie == 0);
    CHECK(!readable(&sm));
    uint32_t svc_handle = got->handle;
    // servicemanager takes its own strong ref, frees the buffer and replies.
    cmd32(&w, BC_ACQUIRE, svc_handle);
    cmd64(&w, BC_FREE_BUFFER, td->data.ptr.buffer);
    int32_t status = 0;
    txn(&w, BC_REPLY, 0, 0, 0, &status, 4, NULL, 0, 0);
    n = wr(&sm, sm1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_COMPLETE, 0);
    n = wr(&s, s1, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_REPLY, 0);
    CHECK(e[1].tr.transaction_data.data_size == 4 && *(const int32_t *)bufp(&e[1]) == 0);
    CHECK(in_map(&s, e[1].tr.transaction_data.data.ptr.buffer));
    cmd64(&w, BC_FREE_BUFFER, e[1].tr.transaction_data.data.ptr.buffer);
    CHECK(wr(&s, s1, &w, e, 32, 0) == 0);

    struct binder_node_info_for_ref ni = {.handle = svc_handle};
    CHECK(bioctl(&sm, sm1, BINDER_GET_NODE_INFO_FOR_REF, &ni) == 0);
    CHECK(ni.strong_count == 1 && ni.weak_count == 1);
    ni = (struct binder_node_info_for_ref){.handle = svc_handle};
    CHECK(bioctl(&s, s1, BINDER_GET_NODE_INFO_FOR_REF, &ni) == -LINUX_EPERM);
    struct binder_node_debug_info di = {0};
    CHECK(bioctl(&s, s1, BINDER_GET_NODE_DEBUG_INFO, &di) == 0);
    CHECK(di.ptr == 0xB0 && di.cookie == 0xC0 && di.has_strong_ref && di.has_weak_ref);
    CHECK(bioctl(&s, s1, BINDER_GET_NODE_DEBUG_INFO, &di) == 0 && di.ptr == 0);

    // The client looks it up; servicemanager answers with the handle, which becomes the
    // client's own handle 1.
    txn(&w, BC_TRANSACTION, 0, GET, 0, "svc", 4, NULL, 0, 0);
    n = wr(&c, c1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_COMPLETE, 0);
    CHECK(wr(&c, c1, NULL, e, 32, 256) == -LINUX_EAGAIN);
    n = wr(&sm, sm1, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_SEC_CTX, 0);
    CHECK(e[1].tr.transaction_data.sender_pid == 300 && !strcmp(bufp(&e[1]), "svc"));
    cmd64(&w, BC_FREE_BUFFER, e[1].tr.transaction_data.data.ptr.buffer);
    struct flat_binder_object ho = handle_obj(svc_handle);
    uint64_t off0[] = {0};
    txn(&w, BC_REPLY, 0, 0, 0, &ho, sizeof ho, off0, 1, 0);
    n = wr(&sm, sm1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_COMPLETE, 0);
    n = wr(&c, c1, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_REPLY, 0);
    got = bufp(&e[1]);
    CHECK(got->type == BINDER_TYPE_HANDLE && got->handle == 1);
    uint32_t ch = got->handle;
    cmd32(&w, BC_INCREFS, ch);
    cmd32(&w, BC_ACQUIRE, ch);
    cmd64(&w, BC_FREE_BUFFER, e[1].tr.transaction_data.data.ptr.buffer);
    CHECK(wr(&c, c1, &w, e, 32, 0) == 0);

    // A call carrying an fd, a scatter-gather tree (parent buffer, child buffer, fd array).
    // The service answers from a looper thread.
    put32(&w, BC_ENTER_LOOPER);
    n = wr(&s, s2, &w, e, 32, 256);
    expect(e, n, BR_NOOP, 0);
    int pfd[2];
    CHECK(pipe(pfd) == 0);
    am_self = c1;
    int cw = am_fd_install(&c.proc, am_file_new(pfd[1], LINUX_O_WRONLY, "pipe:", NULL, NULL), 0, false);
    int cr = am_fd_install(&c.proc, am_file_new(pfd[0], LINUX_O_RDONLY, "pipe:", NULL, NULL), 0, false);
    struct { uint64_t magic, child; int32_t fds[2]; uint8_t pad[40]; } parent = {0x1234, 0, {cw, cr}, {0}};
    char child[] = "child-data";
    struct {
        struct binder_buffer_object p, ch;
        struct binder_fd_array_object fda;
        struct binder_fd_object fd;
    } sg = {
        {BINDER_TYPE_PTR, 0, (uint64_t)&parent, sizeof parent, 0, 0},
        {BINDER_TYPE_PTR, BINDER_BUFFER_FLAG_HAS_PARENT, (uint64_t)child, sizeof child, 0, offsetof(typeof(parent), child)},
        {BINDER_TYPE_FDA, 0, 2, 0, offsetof(typeof(parent), fds)},
        {.type = BINDER_TYPE_FD, .fd = (uint32_t)cw},
    };
    uint64_t sg_offs[] = {0, 40, 80, 112};
    CHECK(sizeof sg == 136);
    txn(&w, BC_TRANSACTION_SG, ch, ECHO, 0, &sg, sizeof sg, sg_offs, 4, sizeof parent + 16);
    n = wr(&c, c1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_COMPLETE, 0);
    n = wr(&s, s2, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION, 0);
    td = &e[1].tr.transaction_data;
    CHECK(td->target.ptr == 0xB0 && td->cookie == 0xC0 && td->code == ECHO && td->sender_pid == 300);
    CHECK(td->flags & TF_ACCEPT_FDS);
    const typeof(sg) *rs = bufp(&e[1]);
    CHECK(in_map(&s, rs->p.buffer) && in_map(&s, rs->ch.buffer));
    const typeof(parent) *rp = (const void *)rs->p.buffer;
    CHECK(rp->magic == 0x1234 && rp->child == rs->ch.buffer);     // parent pointer fixed up
    CHECK(!strcmp((const char *)rp->child, "child-data"));
    for (int i = 0; i < 2; i++) {
        int fd = rp->fds[i];
        CHECK(fd >= 0 && fd < AM_MAX_FDS && s.proc.fds[fd] == c.proc.fds[parent.fds[i]]);
        CHECK(s.proc.cloexec[fd]);
    }
    CHECK(s.proc.fds[rs->fd.fd] == c.proc.fds[cw] && c.proc.fds[cw]->refs == 3);
    CHECK(write(s.proc.fds[rs->fd.fd]->hostfd, "x", 1) == 1);   // the very same pipe
    char x;
    CHECK(read(pfd[0], &x, 1) == 1 && x == 'x');
    uint64_t sbuf = td->data.ptr.buffer;

    // The reply publishes another service node: BR_INCREFS/BR_ACQUIRE reach the replying
    // thread before its BR_TRANSACTION_COMPLETE.
    struct flat_binder_object b1 = binder_obj(0xB1, 0xC1);
    cmd64(&w, BC_FREE_BUFFER, sbuf);
    txn(&w, BC_REPLY, 0, 0, 0, &b1, sizeof b1, off0, 1, 0);
    n = wr(&s, s2, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_INCREFS, BR_ACQUIRE, BR_TRANSACTION_COMPLETE, 0);
    pc = (struct binder_ptr_cookie){0xB1, 0xC1};
    put32(&w, BC_INCREFS_DONE); put(&w, &pc, sizeof pc);
    put32(&w, BC_ACQUIRE_DONE); put(&w, &pc, sizeof pc);
    CHECK(wr(&s, s2, &w, e, 32, 0) == 0);
    n = wr(&c, c1, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_REPLY, 0);
    got = bufp(&e[1]);
    CHECK(got->type == BINDER_TYPE_HANDLE && got->handle == 2);
    // Freeing the reply without taking refs of its own drops the client's only ref: the service
    // is told to release the node.
    cmd64(&w, BC_FREE_BUFFER, e[1].tr.transaction_data.data.ptr.buffer);
    CHECK(wr(&c, c1, &w, e, 32, 0) == 0);
    n = wr(&s, s2, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_RELEASE, BR_DECREFS, 0);
    CHECK(e[1].pc.ptr == 0xB1 && e[2].pc.cookie == 0xC1);

    // Oneway calls to one node are delivered one at a time, each after the previous buffer is
    // freed; their sender pid is 0, as on Linux.
    txn(&w, BC_TRANSACTION, ch, PING, TF_ONE_WAY, "1", 2, NULL, 0, 0);
    txn(&w, BC_TRANSACTION, ch, PING, TF_ONE_WAY, "2", 2, NULL, 0, 0);
    n = wr(&c, c1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_COMPLETE, BR_TRANSACTION_COMPLETE, 0);
    n = wr(&s, s2, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION, 0);
    CHECK((e[1].tr.transaction_data.flags & TF_ONE_WAY) && e[1].tr.transaction_data.sender_pid == 0);
    CHECK(!strcmp(bufp(&e[1]), "1"));
    CHECK(wr(&s, s2, NULL, e, 32, 256) == -LINUX_EAGAIN);
    cmd64(&w, BC_FREE_BUFFER, e[1].tr.transaction_data.data.ptr.buffer);
    n = wr(&s, s2, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION, 0);
    CHECK(!strcmp(bufp(&e[1]), "2"));
    cmd64(&w, BC_FREE_BUFFER, e[1].tr.transaction_data.data.ptr.buffer);
    CHECK(wr(&s, s2, &w, e, 32, 0) == 0);

    // A nested call: while the service handles the client's call, it calls back a binder the
    // client passed in. The client thread waiting for its reply handles it, though it is no
    // looper.
    struct flat_binder_object cb = binder_obj(0xD0, 0xE0);
    txn(&w, BC_TRANSACTION, ch, ECHO, 0, &cb, sizeof cb, off0, 1, 0);
    n = wr(&c, c1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_INCREFS, BR_ACQUIRE, BR_TRANSACTION_COMPLETE, 0);
    pc = (struct binder_ptr_cookie){0xD0, 0xE0};
    put32(&w, BC_INCREFS_DONE); put(&w, &pc, sizeof pc);
    put32(&w, BC_ACQUIRE_DONE); put(&w, &pc, sizeof pc);
    CHECK(wr(&c, c1, &w, e, 32, 0) == 0);
    n = wr(&s, s2, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION, 0);
    got = bufp(&e[1]);
    CHECK(got->type == BINDER_TYPE_HANDLE);
    uint32_t cbh = got->handle;
    uint64_t outer = e[1].tr.transaction_data.data.ptr.buffer;
    txn(&w, BC_TRANSACTION, cbh, PING, 0, "cb", 3, NULL, 0, 0);
    n = wr(&s, s2, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_COMPLETE, 0);
    n = wr(&c, c1, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION, 0);
    CHECK(e[1].tr.transaction_data.target.ptr == 0xD0 && e[1].tr.transaction_data.sender_pid == 200);
    cmd64(&w, BC_FREE_BUFFER, e[1].tr.transaction_data.data.ptr.buffer);
    txn(&w, BC_REPLY, 0, 0, 0, "cb-reply", 9, NULL, 0, 0);
    n = wr(&c, c1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_COMPLETE, 0);
    n = wr(&s, s2, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_REPLY, 0);
    CHECK(!strcmp(bufp(&e[1]), "cb-reply"));
    cmd64(&w, BC_FREE_BUFFER, e[1].tr.transaction_data.data.ptr.buffer);
    cmd64(&w, BC_FREE_BUFFER, outer);
    txn(&w, BC_REPLY, 0, 0, 0, "outer-reply", 12, NULL, 0, 0);
    n = wr(&s, s2, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_COMPLETE, 0);
    n = wr(&c, c1, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_REPLY, 0);
    CHECK(!strcmp(bufp(&e[1]), "outer-reply"));
    cmd64(&w, BC_FREE_BUFFER, e[1].tr.transaction_data.data.ptr.buffer);
    CHECK(wr(&c, c1, &w, e, 32, 0) == 0);
    // The service let go of the callback (its buffer was its only ref). That is process work,
    // which only a looper reads.
    CHECK(wr(&c, c1, NULL, e, 32, 256) == -LINUX_EAGAIN);
    put32(&w, BC_ENTER_LOOPER);
    n = wr(&c, c1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_RELEASE, BR_DECREFS, 0);
    CHECK(e[1].pc.ptr == 0xD0);

    // Errors: an unknown handle fails; fds to a node that does not accept them fail.
    txn(&w, BC_TRANSACTION, 77, PING, 0, "x", 2, NULL, 0, 0);
    n = wr(&c, c1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_FAILED_REPLY, 0);
    n = wr(&h, h1, NULL, e, 32, 256);                    // fresh thread: returns at once
    txn(&w, BC_TRANSACTION, 0, PING, 0, "x", 2, NULL, 0, 0);
    n = wr(&h, h1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_DEAD_REPLY, 0);             // hwbinder has no manager yet

    // Death: the client registers for the service's death, and has a call in flight that the
    // service has read but not answered.
    struct binder_handle_cookie hc = {ch, 0xDEAD};
    put32(&w, BC_REQUEST_DEATH_NOTIFICATION); put(&w, &hc, sizeof hc);
    CHECK(wr(&c, c1, &w, e, 32, 0) == 0);
    txn(&w, BC_TRANSACTION, ch, HANG, 0, "hang", 5, NULL, 0, 0);
    n = wr(&c, c2, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION_COMPLETE, 0);
    n = wr(&s, s2, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_TRANSACTION, 0);
    CHECK(e[1].tr.transaction_data.code == HANG);
    CHECK(!readable(&c));
    gclose(&s, s1);
    CHECK(readable(&c));
    n = wr(&c, c2, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_DEAD_REPLY, 0);
    n = wr(&c, c1, NULL, e, 32, 256);
    expect(e, n, BR_NOOP, BR_DEAD_BINDER, 0);
    CHECK(e[1].cookie == 0xDEAD);
    CHECK(!readable(&c));
    // libbinder's order: clear the registration, then acknowledge the death.
    put32(&w, BC_CLEAR_DEATH_NOTIFICATION); put(&w, &hc, sizeof hc);
    cmd64(&w, BC_DEAD_BINDER_DONE, 0xDEAD);
    n = wr(&c, c1, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_CLEAR_DEATH_NOTIFICATION_DONE, 0);
    CHECK(e[1].cookie == 0xDEAD);
    txn(&w, BC_TRANSACTION, ch, PING, 0, "x", 2, NULL, 0, 0);
    n = wr(&c, c2, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_DEAD_REPLY, 0);
    // A late registration on a dead binder fires at once (to the non-looper caller itself).
    hc.cookie = 0xD1;
    put32(&w, BC_REQUEST_DEATH_NOTIFICATION); put(&w, &hc, sizeof hc);
    n = wr(&c, c2, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_DEAD_BINDER, 0);
    CHECK(e[1].cookie == 0xD1);
    cmd64(&w, BC_DEAD_BINDER_DONE, 0xD1);
    put32(&w, BC_CLEAR_DEATH_NOTIFICATION); put(&w, &hc, sizeof hc);
    n = wr(&c, c2, &w, e, 32, 256);
    expect(e, n, BR_NOOP, BR_CLEAR_DEATH_NOTIFICATION_DONE, 0);
    // Dropping the last refs to the dead node frees it.
    cmd32(&w, BC_RELEASE, ch);
    cmd32(&w, BC_DECREFS, ch);
    CHECK(wr(&c, c1, &w, e, 32, 0) == 0);
    cmd32(&w, BC_RELEASE, svc_handle);
    n = wr(&sm, sm1, &w, e, 32, 256);
    CHECK(n == -LINUX_EAGAIN);
    cmd32(&w, BINDER_THREAD_EXIT, 0);   // an ioctl, not a command: the write fails
    CHECK(wr(&c, c1, &w, e, 32, 0) == -LINUX_EINVAL);
    CHECK(bioctl(&c, c2, BINDER_THREAD_EXIT, &(int){0}) == 0);

    // The fds the service received went with... nothing: they stay in its table. Closing
    // everything releases every process.
    gclose(&c, c1);
    gclose(&sm, sm1);
    gclose(&h, h1);
    printf("part A ok\n");
}

// ---- part B: threads ---------------------------------------------------------------------
enum { CLIENTS = 4, CALLS = 2000 };
static gproc bsm, bs, bc;
static volatile int s_dying;
static int s_busy;
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t s_pool;
static volatile int hang_seen, echoes;

// The context manager: a blocking looper that keeps one service and quits on code 99.
static void *sm_main(void *arg) {
    am_thread *t = mkthread(&bsm, 1100);
    struct flat_binder_object mgr = {.type = BINDER_TYPE_BINDER, .flags = FLAT_BINDER_FLAG_ACCEPTS_FDS};
    CHECK(bioctl(&bsm, t, BINDER_SET_CONTEXT_MGR_EXT, &mgr) == 0);
    cmdbuf w = {0};
    ev e[32];
    put32(&w, BC_ENTER_LOOPER);
    uint32_t svc = 0;
    for (bool quit = false; !quit;) {
        int n = wr(&bsm, t, &w, e, 32, 1024);
        CHECK(n >= 0);
        for (int i = 0; i < n; i++) {
            if (e[i].cmd != BR_TRANSACTION) continue;
            struct binder_transaction_data *td = &e[i].tr.transaction_data;
            const struct flat_binder_object *o = bufp(&e[i]);
            if (td->code == ADD) { svc = o->handle; cmd32(&w, BC_ACQUIRE, svc); }
            quit = td->code == 99;
            cmd64(&w, BC_FREE_BUFFER, td->data.ptr.buffer);
            static struct flat_binder_object ho;
            static uint64_t off0[] = {0};
            ho = handle_obj(svc);
            if (td->code == GET) txn(&w, BC_REPLY, 0, 0, 0, &ho, sizeof ho, off0, 1, 0);
            else txn(&w, BC_REPLY, 0, 0, 0, "ok", 3, NULL, 0, 0);
        }
    }
    CHECK(wr(&bsm, t, &w, e, 32, 0) == 0);
    return NULL;
}

// A service looper. Its file is nonblocking and it waits in poll() on the binder fd, the way a
// libbinder Looper does; that also lets it stop cleanly before the process dies.
static void *svc_loop(void *arg) {
    am_thread *t = mkthread(&bs, (int)(intptr_t)arg);
    cmdbuf w = {0};
    ev e[32];
    put32(&w, t->tid == 1200 ? BC_ENTER_LOOPER : BC_REGISTER_LOOPER);
    for (;;) {
        pthread_mutex_lock(&s_lock);
        if (s_dying) { pthread_mutex_unlock(&s_lock); break; }
        s_busy++;
        pthread_mutex_unlock(&s_lock);
        struct pollfd p = {bs.f->hostfd, POLLIN, 0};
        poll(&p, 1, 20);
        int n = wr(&bs, t, &w, e, 32, 1024);
        CHECK(n >= 0 || n == -LINUX_EAGAIN);
        for (int i = 0; i < n; i++) {
            switch (e[i].cmd) {
            case BR_SPAWN_LOOPER:
                CHECK(t->tid == 1200 && !s_pool);
                pthread_create(&s_pool, NULL, svc_loop, (void *)1201);
                break;
            case BR_INCREFS: case BR_ACQUIRE:
                put32(&w, e[i].cmd == BR_INCREFS ? BC_INCREFS_DONE : BC_ACQUIRE_DONE);
                put(&w, &e[i].pc, sizeof e[i].pc);
                break;
            case BR_TRANSACTION: {
                struct binder_transaction_data *td = &e[i].tr.transaction_data;
                if (td->code == HANG) { hang_seen = 1; break; }   // never answered
                CHECK(td->code == ECHO && td->target.ptr == 0x5E && td->sender_pid == 1300);
                static __thread uint8_t out[64];
                memcpy(out, bufp(&e[i]), td->data_size);
                cmd64(&w, BC_FREE_BUFFER, td->data.ptr.buffer);
                txn(&w, BC_REPLY, 0, 0, 0, out, td->data_size, NULL, 0, 0);
                __atomic_add_fetch(&echoes, 1, __ATOMIC_RELAXED);
                break;
            }
            }
        }
        if (w.n) CHECK(wr(&bs, t, &w, e, 32, 0) == 0);
        pthread_mutex_lock(&s_lock);
        s_busy--;
        pthread_mutex_unlock(&s_lock);
    }
    return NULL;
}

static uint32_t b_svc;

static void *client(void *arg) {
    int k = (int)(intptr_t)arg;
    am_thread *t = mkthread(&bc, 1310 + k);
    cmdbuf w = {0};
    ev e[32];
    for (int i = 0; i < CALLS; i++) {
        struct { int k, i; } msg = {k, i};
        txn(&w, BC_TRANSACTION, b_svc, ECHO, 0, &msg, sizeof msg, NULL, 0, 0);
        // libbinder's waitForResponse: read until the reply.
        const ev *rep = NULL;
        while (!rep) {
            int n = wr(&bc, t, w.n ? &w : NULL, e, 32, 256);
            CHECK(n > 0);
            for (int j = 0; j < n; j++) CHECK(e[j].cmd == BR_NOOP || e[j].cmd == BR_TRANSACTION_COMPLETE || e[j].cmd == BR_REPLY);
            rep = find(e, n, BR_REPLY);
        }
        CHECK(rep->tr.transaction_data.data_size == sizeof msg && !memcmp(bufp(rep), &msg, sizeof msg));
        cmd64(&w, BC_FREE_BUFFER, rep->tr.transaction_data.data.ptr.buffer);
    }
    CHECK(wr(&bc, t, &w, e, 32, 0) == 0);
    return NULL;
}

static uint32_t hang_result;
static void *hanger(void *arg) {
    am_thread *t = mkthread(&bc, 1320);
    cmdbuf w = {0};
    ev e[32];
    txn(&w, BC_TRANSACTION, b_svc, HANG, 0, "h", 2, NULL, 0, 0);
    for (;;) {
        int n = wr(&bc, t, w.n ? &w : NULL, e, 32, 256);
        CHECK(n > 0);
        for (int j = 0; j < n; j++)
            if (e[j].cmd == BR_DEAD_REPLY || e[j].cmd == BR_REPLY || e[j].cmd == BR_FAILED_REPLY) hang_result = e[j].cmd;
        if (hang_result) return NULL;
    }
}

static uint64_t death_cookie;
static void *death_waiter(void *arg) {
    am_thread *t = mkthread(&bc, 1330);
    cmdbuf w = {0};
    ev e[32];
    struct binder_handle_cookie hc = {b_svc, 0xFEED};
    put32(&w, BC_ENTER_LOOPER);
    put32(&w, BC_REQUEST_DEATH_NOTIFICATION); put(&w, &hc, sizeof hc);
    while (!death_cookie) {
        int n = wr(&bc, t, w.n ? &w : NULL, e, 32, 256);   // blocks once registered
        CHECK(n > 0);
        const ev *d = find(e, n, BR_DEAD_BINDER);
        if (d) death_cookie = d->cookie;
    }
    put32(&w, BC_CLEAR_DEATH_NOTIFICATION); put(&w, &hc, sizeof hc);
    cmd64(&w, BC_DEAD_BINDER_DONE, 0xFEED);
    for (;;) {
        int n = wr(&bc, t, &w, e, 32, 256);
        CHECK(n > 0);
        if (find(e, n, BR_CLEAR_DEATH_NOTIFICATION_DONE)) break;
    }
    return NULL;
}

static void part_b(void) {
    gproc_init(&bsm, 1100); gproc_init(&bs, 1200); gproc_init(&bc, 1300);
    am_thread *sm0 = mkthread(&bsm, 1100), *s0 = mkthread(&bs, 1200), *c0 = mkthread(&bc, 1300);
    gopen(&bsm, sm0, "/dev/vndbinder", false);
    gopen(&bs, s0, "/dev/vndbinder", true);
    gopen(&bc, c0, "/dev/vndbinder", false);
    pthread_t smt;
    pthread_create(&smt, NULL, sm_main, NULL);
    usleep(20000);   // let it become the context manager

    // The service registers from its main thread (blocking on the poll'd fd), then loops.
    uint32_t one = 1;
    CHECK(bioctl(&bs, s0, BINDER_SET_MAX_THREADS, &one) == 0);
    cmdbuf w = {0};
    ev e[32];
    struct flat_binder_object so = binder_obj(0x5E, 0x5F);
    uint64_t off0[] = {0};
    txn(&w, BC_TRANSACTION, 0, ADD, 0, &so, sizeof so, off0, 1, 0);
    for (bool done = false; !done;) {
        struct pollfd p = {bs.f->hostfd, POLLIN, 0};
        int n = wr(&bs, s0, w.n ? &w : NULL, e, 32, 256);
        if (n == -LINUX_EAGAIN) { poll(&p, 1, 100); continue; }   // a non-looper waits on its own todo,
        CHECK(n > 0);                                             // which poll does not show: retry
        for (int i = 0; i < n; i++) {
            if (e[i].cmd == BR_INCREFS || e[i].cmd == BR_ACQUIRE) {
                put32(&w, e[i].cmd == BR_INCREFS ? BC_INCREFS_DONE : BC_ACQUIRE_DONE);
                put(&w, &e[i].pc, sizeof e[i].pc);
            }
            if (e[i].cmd == BR_REPLY) { cmd64(&w, BC_FREE_BUFFER, e[i].tr.transaction_data.data.ptr.buffer); done = true; }
        }
    }
    if (w.n) CHECK(wr(&bs, s0, &w, e, 32, 0) == 0);
    pthread_t st;
    pthread_create(&st, NULL, svc_loop, (void *)1200);

    // The client looks the service up (blocking), then calls it from several threads at once.
    txn(&w, BC_TRANSACTION, 0, GET, 0, "s", 2, NULL, 0, 0);
    for (b_svc = 0; !b_svc;) {
        int n = wr(&bc, c0, w.n ? &w : NULL, e, 32, 256);
        CHECK(n > 0);
        const ev *r = find(e, n, BR_REPLY);
        if (!r) continue;
        const struct flat_binder_object *o = bufp(r);
        CHECK(o->type == BINDER_TYPE_HANDLE);
        b_svc = o->handle;
        cmd32(&w, BC_ACQUIRE, b_svc);
        cmd64(&w, BC_FREE_BUFFER, r->tr.transaction_data.data.ptr.buffer);
        CHECK(wr(&bc, c0, &w, e, 32, 0) == 0);
    }
    pthread_t ct[CLIENTS];
    for (int k = 0; k < CLIENTS; k++) pthread_create(&ct[k], NULL, client, (void *)(intptr_t)k);
    for (int k = 0; k < CLIENTS; k++) pthread_join(ct[k], NULL);
    CHECK(echoes == CLIENTS * CALLS);
    CHECK(s_pool);   // the service was asked to spawn a looper, and did
    printf("part B: %d echo calls from %d threads ok\n", echoes, CLIENTS);

    // Death while a call hangs in the service and another thread waits for the notification.
    pthread_t ht, dt;
    pthread_create(&dt, NULL, death_waiter, NULL);
    pthread_create(&ht, NULL, hanger, NULL);
    while (!hang_seen) usleep(1000);
    usleep(20000);
    pthread_mutex_lock(&s_lock);
    s_dying = 1;
    pthread_mutex_unlock(&s_lock);
    for (;;) {
        pthread_mutex_lock(&s_lock);
        int b = s_busy;
        pthread_mutex_unlock(&s_lock);
        if (!b) break;
        usleep(1000);
    }
    pthread_join(st, NULL);
    pthread_join(s_pool, NULL);
    gclose(&bs, s0);
    pthread_join(ht, NULL);
    pthread_join(dt, NULL);
    CHECK(hang_result == BR_DEAD_REPLY && death_cookie == 0xFEED);
    printf("part B: death ok (pending call got BR_DEAD_REPLY, notification delivered)\n");

    // Stop the manager with a call, then close everything.
    txn(&w, BC_TRANSACTION, 0, 99, 0, "q", 2, NULL, 0, 0);
    for (bool done = false; !done;) {
        int n = wr(&bc, c0, w.n ? &w : NULL, e, 32, 256);
        CHECK(n > 0);
        const ev *r = find(e, n, BR_REPLY);
        if (r) { cmd64(&w, BC_FREE_BUFFER, r->tr.transaction_data.data.ptr.buffer); done = true; }
    }
    CHECK(wr(&bc, c0, &w, e, 32, 0) == 0);
    pthread_join(smt, NULL);
    gclose(&bc, c0);
    gclose(&bsm, sm0);
    printf("part B ok\n");
}

int main(void) {
    char dir[] = "/tmp/binder-test.XXXXXX";
    const char *tmp = getenv("TMPDIR");
    static char path[1024];
    snprintf(path, sizeof path, "%s/binder-test.XXXXXX", tmp ? tmp : "/tmp");
    am_datadir = mkdtemp(path) ? path : mkdtemp(dir);
    am_strace = getenv("AM_STRACE") != NULL;
    am_binder_init();
    part_a();
    part_b();
    printf("binder test passed\n");
    return 0;
}
