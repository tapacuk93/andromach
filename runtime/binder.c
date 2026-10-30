// Binder: /dev/binder, /dev/hwbinder and /dev/vndbinder, the kernel driver as part of the
// runtime. It follows drivers/android/binder.c closely enough for libbinder and servicemanager:
// nodes, refs, per-thread transaction stacks, todo queues, oneway queues per node, death
// notifications, and the translation of binders, handles, fds and scatter-gather buffers.
//
// Every guest process lives in this one host process, so "copying into the target" is a memcpy
// into the receiver's mapped buffer area, and passing an fd shares the am_file. One mutex guards
// the whole driver, as the old kernel's binder_main_lock did; each binder thread sleeps on its
// own condition variable.
#include "am.h"
#include "linux.h"
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ALIGN8(x) (((x) + 7) & ~(uint64_t)7)
#define MAX_MAP (4u << 20)   // the kernel caps a binder mapping at 4 MB
#define SECCTX "u:r:su:s0"   // no SELinux labels here; every sender gets this context

// ---- lists -------------------------------------------------------------------------------
typedef struct list { struct list *prev, *next; } list;
#define LIST_INIT(l) ((l)->prev = (l)->next = (l))
#define container_of(p, T, m) ((T *)((char *)(p) - offsetof(T, m)))
#define list_for(it, head) for (list *it = (head)->next, *it##_n = it->next; it != (head); it = it##_n, it##_n = it->next)
static bool list_empty(const list *l) { return l->next == l; }
static void list_add_tail(list *h, list *e) { e->prev = h->prev; e->next = h; h->prev->next = e; h->prev = e; }
static void list_add_before(list *pos, list *e) { list_add_tail(pos, e); }
static void list_del(list *e) { e->prev->next = e->next; e->next->prev = e->prev; LIST_INIT(e); }
static list *list_pop(list *h) {
    if (list_empty(h)) return NULL;
    list *e = h->next;
    list_del(e);
    return e;
}

// ---- objects -----------------------------------------------------------------------------
enum { W_TRANSACTION = 1, W_RETURN, W_NODE, W_DEAD_BINDER, W_DEAD_BINDER_AND_CLEAR, W_CLEAR_DEATH };

typedef struct work { list entry; int type; } work;
typedef struct ret_work { work w; uint32_t cmd; } ret_work;   // BR_TRANSACTION_COMPLETE, errors

typedef struct bproc bproc;
typedef struct bthread bthread;
typedef struct btxn btxn;

typedef struct bctx { const char *name; struct bnode *mgr; } bctx;

typedef struct bnode {
    list entry;              // in its proc's nodes, or dead_nodes once the proc is gone
    bproc *proc;
    uint64_t ptr, cookie;
    uint32_t flags;
    int internal_strong, local_strong, local_weak;
    bool has_strong, has_weak, pending_strong, pending_weak;
    list refs;
    work w;                  // W_NODE: tell the owner about ref count changes
    bool has_async;
    list async_todo;
} bnode;

typedef struct bdeath { work w; uint64_t cookie; } bdeath;

typedef struct bref {
    list proc_entry, node_entry;
    bproc *proc;
    bnode *node;
    uint32_t desc;
    int strong, weak;
    bdeath *death;
} bref;

typedef struct fdfix { uint64_t off; am_file *f; } fdfix;

typedef struct bbuf {
    list entry;
    uint64_t off, size;
    uint64_t data_size, offsets_size;
    bool user_free, async, clear;
    btxn *txn;
    bnode *target;           // holds a local strong ref on the node while the buffer lives
    fdfix *fix;              // fds installed in the receiver when it reads the transaction
    int nfix;
} bbuf;

struct btxn {
    work w;
    bthread *from;           // sync sender, NULL for oneway or once the sender has gone
    int from_pid;
    btxn *from_parent, *to_parent;
    bproc *to_proc;
    bthread *to_thread;
    bbuf *buf;
    uint32_t code, flags;
    bool reply;
    uint64_t secctx;         // guest address of the security context string, or 0
};

enum { LOOPER_REGISTERED = 1, LOOPER_ENTERED = 2, LOOPER_EXITED = 4 };

struct bthread {
    list entry;
    bproc *proc;
    int tid;
    uint32_t looper;
    bool need_return;        // a fresh thread's first read returns at once, as on Linux
    bool waiting, error_pending;
    int in_ioctl;
    btxn *stack;
    list todo;
    list wait_entry;         // in proc->waiting while blocked for process work
    pthread_cond_t cond;
};

struct bproc {
    bctx *ctx;
    am_proc *aproc;
    int pid;
    list threads, nodes, refs, todo, delivered_death, waiting;
    uint8_t *rw;             // the runtime's writable alias of the mapping
    uint64_t ubase, size;    // the guest's read-only view
    list bufs;               // sorted by offset
    int max_threads, requested, started;
    int pipe_r, pipe_w;      // readable while work is pending, for poll/epoll on the binder fd
    bool pipe_ready, dead;
    int busy;                // ioctls in progress; the last one out frees a released proc
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static bctx contexts[3] = {{.name = "binder"}, {.name = "hwbinder"}, {.name = "vndbinder"}};
static list dead_nodes = {&dead_nodes, &dead_nodes};

static void trace(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void trace(const char *fmt, ...) {
    if (!am_strace) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[binder] ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

// ---- waking and polling ------------------------------------------------------------------
static bool proc_work_ok(bthread *t) {
    return !t->stack && list_empty(&t->todo) && (t->looper & (LOOPER_REGISTERED | LOOPER_ENTERED));
}

// The pipe is readable while a reader would find work: process work, or work queued for a
// looper thread that is not inside an ioctl (Linux's binder_poll checks the polling thread).
static void poll_update(bproc *p) {
    bool want = !list_empty(&p->todo);
    if (!want)
        list_for(e, &p->threads) {
            bthread *t = container_of(e, bthread, entry);
            if (!t->in_ioctl && (t->looper & (LOOPER_REGISTERED | LOOPER_ENTERED)) && !list_empty(&t->todo)) {
                want = true;
                break;
            }
        }
    if (want == p->pipe_ready) return;
    char c = 0;
    if (want) { if (write(p->pipe_w, &c, 1) != 1) return; }
    else if (read(p->pipe_r, &c, 1) != 1) return;
    p->pipe_ready = want;
}

static void queue_thread(bthread *t, work *w) {
    list_add_tail(&t->todo, &w->entry);
    pthread_cond_signal(&t->cond);
    poll_update(t->proc);
}

static void queue_proc(bproc *p, work *w) {
    list_add_tail(&p->todo, &w->entry);
    if (!list_empty(&p->waiting)) {
        bthread *t = container_of(p->waiting.next, bthread, wait_entry);
        list_del(&t->wait_entry);
        pthread_cond_signal(&t->cond);
    }
    poll_update(p);
}

static void queue_return(bthread *t, uint32_t cmd) {
    ret_work *r = calloc(1, sizeof *r);
    r->w.type = W_RETURN;
    r->cmd = cmd;
    if (cmd != BR_TRANSACTION_COMPLETE) t->error_pending = true;
    queue_thread(t, &r->w);
}

// Queue on the calling thread when it is not a looper (it reads its own results), else on the
// process, as the kernel does for death notifications.
static void queue_self_or_proc(bthread *t, work *w) {
    if (t && !(t->looper & (LOOPER_REGISTERED | LOOPER_ENTERED))) queue_thread(t, w);
    else queue_proc(t->proc, w);
}

// ---- nodes and refs ----------------------------------------------------------------------
static bnode *node_get(bproc *p, uint64_t ptr) {
    list_for(e, &p->nodes) {
        bnode *n = container_of(e, bnode, entry);
        if (n->ptr == ptr) return n;
    }
    return NULL;
}

static bnode *node_new(bproc *p, uint64_t ptr, uint64_t cookie, uint32_t flags) {
    bnode *n = calloc(1, sizeof *n);
    n->proc = p;
    n->ptr = ptr;
    n->cookie = cookie;
    n->flags = flags;
    LIST_INIT(&n->refs);
    LIST_INIT(&n->w.entry);
    LIST_INIT(&n->async_todo);
    n->w.type = W_NODE;
    list_add_tail(&p->nodes, &n->entry);
    return n;
}

static void node_free(bnode *n) {
    list_del(&n->entry);
    list_del(&n->w.entry);
    free(n);
}

// binder_inc_node: target, when given, is the sending thread's todo, so the owner hears of a
// newly published node (BR_INCREFS/BR_ACQUIRE) before its transaction completes.
static void node_inc(bnode *n, bool strong, bool internal, bthread *target) {
    if (strong) {
        if (internal) n->internal_strong++;
        else n->local_strong++;
        if (!n->has_strong && target) {
            list_del(&n->w.entry);
            queue_thread(target, &n->w);
        }
    } else {
        if (!internal) n->local_weak++;
        if (!n->has_weak && list_empty(&n->w.entry) && target) queue_thread(target, &n->w);
    }
}

// binder_dec_node: when nothing references the node any more, either tell its owner (which
// still holds refs for us) or free it.
static void node_dec(bnode *n, bool strong, bool internal) {
    if (strong) {
        if (internal) n->internal_strong--;
        else n->local_strong--;
        if (n->local_strong || n->internal_strong) return;
    } else {
        if (!internal) n->local_weak--;
        if (n->local_weak || !list_empty(&n->refs)) return;
    }
    if (n->proc && (n->has_strong || n->has_weak)) {
        if (list_empty(&n->w.entry)) queue_proc(n->proc, &n->w);
    } else if (list_empty(&n->refs) && !n->local_strong && !n->local_weak && !n->internal_strong) {
        node_free(n);
    }
}

static bref *ref_by_desc(bproc *p, uint32_t desc) {
    list_for(e, &p->refs) {
        bref *r = container_of(e, bref, proc_entry);
        if (r->desc == desc) return r;
    }
    return NULL;
}

// The proc's ref to a node, made if needed with the lowest free handle (0 only for the
// context manager). p->refs stays sorted by handle.
static bref *ref_for_node(bproc *p, bnode *n) {
    list_for(e, &p->refs) {
        bref *r = container_of(e, bref, proc_entry);
        if (r->node == n) return r;
    }
    bref *r = calloc(1, sizeof *r);
    r->proc = p;
    r->node = n;
    r->desc = n == p->ctx->mgr ? 0 : 1;
    list *pos = &p->refs;
    list_for(e, &p->refs) {
        bref *o = container_of(e, bref, proc_entry);
        if (o->desc < r->desc) continue;
        if (o->desc == r->desc) { r->desc++; continue; }
        pos = e;
        break;
    }
    list_add_before(pos, &r->proc_entry);
    list_add_tail(&n->refs, &r->node_entry);
    return r;
}

static void ref_inc(bref *r, bool strong, bthread *target) {
    if (strong) {
        if (!r->strong++) node_inc(r->node, true, true, target);
    } else {
        if (!r->weak++) node_inc(r->node, false, true, target);
    }
}

static void ref_free(bref *r) {
    bnode *n = r->node;
    if (r->strong) node_dec(n, true, true);
    list_del(&r->node_entry);
    list_del(&r->proc_entry);
    if (r->death) { list_del(&r->death->w.entry); free(r->death); }
    free(r);
    node_dec(n, false, true);
}

static int ref_dec(bref *r, bool strong) {
    if (strong) {
        if (!r->strong) return AM_ERR(LINUX_EINVAL);
        if (!--r->strong) node_dec(r->node, true, true);
    } else {
        if (!r->weak) return AM_ERR(LINUX_EINVAL);
        r->weak--;
    }
    if (!r->strong && !r->weak) ref_free(r);
    return 0;
}

// BC_INCREFS/ACQUIRE/RELEASE/DECREFS. Handle 0 names the context manager even before the
// process holds a ref to it.
static int ref_update(bproc *p, uint32_t desc, bool inc, bool strong) {
    bref *r = ref_by_desc(p, desc);
    if (!r && desc == 0 && inc && p->ctx->mgr) {
        if (p->ctx->mgr->proc == p) return AM_ERR(LINUX_EINVAL);
        r = ref_for_node(p, p->ctx->mgr);
    }
    if (!r) return AM_ERR(LINUX_EINVAL);
    if (inc) { ref_inc(r, strong, NULL); return 0; }
    return ref_dec(r, strong);
}

// ---- buffers -----------------------------------------------------------------------------
static bbuf *buf_alloc(bproc *p, uint64_t size) {
    if (!p->rw || p->dead) return NULL;
    size = ALIGN8(size ? size : 8);
    uint64_t at = 0;
    list *pos = &p->bufs;
    list_for(e, &p->bufs) {
        bbuf *b = container_of(e, bbuf, entry);
        if (b->off - at >= size) { pos = e; break; }
        at = b->off + b->size;
    }
    if (pos == &p->bufs && p->size - at < size) return NULL;
    bbuf *b = calloc(1, sizeof *b);
    b->off = at;
    b->size = size;
    list_add_before(pos, &b->entry);
    return b;
}

static bbuf *buf_find(bproc *p, uint64_t uaddr) {
    list_for(e, &p->bufs) {
        bbuf *b = container_of(e, bbuf, entry);
        if (p->ubase + b->off == uaddr) return b;
    }
    return NULL;
}

static void *rw_at(bproc *p, uint64_t uaddr) { return p->rw + (uaddr - p->ubase); }

// binder_transaction_buffer_release: drop what translation took for the receiver, for the first
// `nobj` objects (all of them for a delivered buffer).
static void buf_release_objects(bproc *p, bbuf *b, uint64_t nobj) {
    uint8_t *data = p->rw + b->off;
    const uint64_t *offs = (const uint64_t *)(data + ALIGN8(b->data_size));
    uint64_t n = b->offsets_size / 8;
    if (nobj < n) n = nobj;
    for (uint64_t i = 0; i < n; i++) {
        if (offs[i] + 4 > b->data_size) continue;
        struct flat_binder_object *fp = (void *)(data + offs[i]);
        switch (fp->type) {
        case BINDER_TYPE_BINDER: case BINDER_TYPE_WEAK_BINDER: {
            bnode *nd = node_get(p, fp->binder);
            if (nd) node_dec(nd, fp->type == BINDER_TYPE_BINDER, false);
            break;
        }
        case BINDER_TYPE_HANDLE: case BINDER_TYPE_WEAK_HANDLE:
            ref_update(p, fp->handle, false, fp->type == BINDER_TYPE_HANDLE);
            break;
        }
    }
}

static void buf_free(bproc *p, bbuf *b, bool release) {
    if (b->txn) b->txn->buf = NULL;
    if (release) buf_release_objects(p, b, UINT64_MAX);
    for (int i = 0; i < b->nfix; i++) am_file_put(b->fix[i].f);
    free(b->fix);
    if (b->target) node_dec(b->target, true, false);
    if (b->clear) memset(p->rw + b->off, 0, b->size);
    list_del(&b->entry);
    free(b);
}

// ---- transactions ------------------------------------------------------------------------
static void txn_free(btxn *t) {
    if (t->buf) t->buf->txn = NULL;
    list_del(&t->w.entry);
    free(t);
}

// A transaction no one will read any more: a buffer the receiver has not seen is freed, one it
// has seen is left for its BC_FREE_BUFFER.
static void txn_drop_buf(btxn *t) {
    bbuf *b = t->buf;
    if (!b) return;
    t->buf = NULL;
    b->txn = NULL;
    if (!b->user_free) buf_free(t->to_proc, b, true);
}

static void stack_pop(bthread *t, btxn *x) {
    if (t->stack == x) t->stack = x->from_parent;
}

// binder_send_failed_reply: the receiver of a sync transaction is gone; tell the sender, or the
// first sender still alive further up a chain of nested calls.
static void send_failed_reply(btxn *t, uint32_t cmd) {
    while (t) {
        bthread *from = t->from;
        if (from) {
            stack_pop(from, t);
            txn_drop_buf(t);
            txn_free(t);
            queue_return(from, cmd);
            return;
        }
        btxn *next = t->from_parent;
        txn_drop_buf(t);
        txn_free(t);
        t = next;
    }
}

// Copies the sender's data into a new buffer of the target and translates the objects in it.
// Returns 0 or the BR_ error for the sender.
static uint32_t translate(bproc *from, bthread *thread, bproc *to, bbuf *b, const struct binder_transaction_data *tr,
                          uint64_t extra, bool allow_fds, uint64_t *done) {
    uint8_t *data = to->rw + b->off;
    uint64_t *offs = (uint64_t *)(data + ALIGN8(tr->data_size));
    memcpy(data, (void *)tr->data.ptr.buffer, tr->data_size);
    memcpy(offs, (void *)tr->data.ptr.offsets, tr->offsets_size);
    uint64_t sg = ALIGN8(tr->data_size) + ALIGN8(tr->offsets_size), sg_end = sg + extra;
    uint64_t n = tr->offsets_size / 8, min = 0;
    for (uint64_t i = 0; i < n; i++, *done = i) {
        uint64_t off = offs[i];
        if (off < min || off % 4 || off + 8 > tr->data_size) return BR_FAILED_REPLY;
        uint32_t type = *(uint32_t *)(data + off);
        uint64_t osz = type == BINDER_TYPE_PTR ? sizeof(struct binder_buffer_object)
                     : type == BINDER_TYPE_FDA ? sizeof(struct binder_fd_array_object)
                     : sizeof(struct flat_binder_object);
        if (off + osz > tr->data_size) return BR_FAILED_REPLY;
        min = off + osz;
        switch (type) {
        case BINDER_TYPE_BINDER: case BINDER_TYPE_WEAK_BINDER: {
            struct flat_binder_object *fp = (void *)(data + off);
            bool strong = type == BINDER_TYPE_BINDER;
            bnode *nd = node_get(from, fp->binder);
            if (!nd) nd = node_new(from, fp->binder, fp->cookie, fp->flags);
            else if (nd->cookie != fp->cookie) return BR_FAILED_REPLY;
            bref *r = ref_for_node(to, nd);
            ref_inc(r, strong, thread);
            fp->type = strong ? BINDER_TYPE_HANDLE : BINDER_TYPE_WEAK_HANDLE;
            fp->binder = 0;
            fp->handle = r->desc;
            fp->cookie = 0;
            break;
        }
        case BINDER_TYPE_HANDLE: case BINDER_TYPE_WEAK_HANDLE: {
            struct flat_binder_object *fp = (void *)(data + off);
            bool strong = type == BINDER_TYPE_HANDLE;
            bref *r = ref_by_desc(from, fp->handle);
            if (!r || (strong && !r->strong)) return BR_FAILED_REPLY;
            bnode *nd = r->node;
            if (nd->proc == to) {
                fp->type = strong ? BINDER_TYPE_BINDER : BINDER_TYPE_WEAK_BINDER;
                fp->binder = nd->ptr;
                fp->cookie = nd->cookie;
                node_inc(nd, strong, false, NULL);
            } else {
                bref *dr = ref_for_node(to, nd);
                ref_inc(dr, strong, NULL);
                fp->binder = 0;
                fp->handle = dr->desc;
                fp->cookie = 0;
            }
            break;
        }
        case BINDER_TYPE_FD: {
            struct binder_fd_object *fo = (void *)(data + off);
            if (!allow_fds) return BR_FAILED_REPLY;
            am_file *f = fo->fd < AM_MAX_FDS ? from->aproc->fds[fo->fd] : NULL;
            if (!f) return BR_FAILED_REPLY;
            __atomic_add_fetch(&f->refs, 1, __ATOMIC_ACQ_REL);
            b->fix = realloc(b->fix, (b->nfix + 1) * sizeof *b->fix);
            b->fix[b->nfix++] = (fdfix){off + offsetof(struct binder_fd_object, fd), f};
            fo->pad_binder = 0;
            break;
        }
        case BINDER_TYPE_PTR: {
            struct binder_buffer_object *bo = (void *)(data + off);
            uint64_t len = ALIGN8(bo->length);
            if (len < bo->length || sg_end - sg < len) return BR_FAILED_REPLY;
            memcpy(data + sg, (void *)bo->buffer, bo->length);
            bo->buffer = to->ubase + b->off + sg;
            sg += len;
            if (bo->flags & BINDER_BUFFER_FLAG_HAS_PARENT) {
                if (bo->parent >= i || offs[bo->parent] + sizeof *bo > tr->data_size) return BR_FAILED_REPLY;
                struct binder_buffer_object *pb = (void *)(data + offs[bo->parent]);
                if (pb->type != BINDER_TYPE_PTR || bo->parent_offset + 8 > pb->length) return BR_FAILED_REPLY;
                memcpy(rw_at(to, pb->buffer + bo->parent_offset), &bo->buffer, 8);
            }
            break;
        }
        case BINDER_TYPE_FDA: {
            struct binder_fd_array_object *fa = (void *)(data + off);
            if (!allow_fds) return BR_FAILED_REPLY;
            if (fa->parent >= i || offs[fa->parent] + sizeof(struct binder_buffer_object) > tr->data_size)
                return BR_FAILED_REPLY;
            struct binder_buffer_object *pb = (void *)(data + offs[fa->parent]);
            if (pb->type != BINDER_TYPE_PTR || fa->parent_offset % 4 || fa->num_fds > pb->length / 4 ||
                fa->parent_offset + fa->num_fds * 4 > pb->length)
                return BR_FAILED_REPLY;
            uint64_t at = pb->buffer + fa->parent_offset;   // guest address in the target buffer
            for (uint64_t k = 0; k < fa->num_fds; k++) {
                uint32_t *slot = rw_at(to, at + 4 * k);
                am_file *f = *slot < AM_MAX_FDS ? from->aproc->fds[*slot] : NULL;
                if (!f) return BR_FAILED_REPLY;
                __atomic_add_fetch(&f->refs, 1, __ATOMIC_ACQ_REL);
                b->fix = realloc(b->fix, (b->nfix + 1) * sizeof *b->fix);
                b->fix[b->nfix++] = (fdfix){at + 4 * k - to->ubase - b->off, f};
            }
            break;
        }
        default:
            return BR_FAILED_REPLY;
        }
    }
    return 0;
}

// binder_transaction: BC_TRANSACTION(_SG) and BC_REPLY(_SG).
static void transact(bproc *proc, bthread *thread, const struct binder_transaction_data *tr, bool reply, uint64_t extra) {
    btxn *in_reply_to = NULL;
    bthread *target_thread = NULL;
    bproc *target = NULL;
    bnode *node = NULL;
    uint32_t err = 0;

    if (reply) {
        in_reply_to = thread->stack;
        if (!in_reply_to || in_reply_to->to_thread != thread) {
            queue_return(thread, BR_FAILED_REPLY);
            return;
        }
        thread->stack = in_reply_to->to_parent;
        target_thread = in_reply_to->from;
        if (!target_thread || target_thread->proc->dead) { err = BR_DEAD_REPLY; goto fail; }
        if (target_thread->stack != in_reply_to) { err = BR_FAILED_REPLY; goto fail; }
        target = target_thread->proc;
    } else {
        if (tr->target.handle) {
            bref *r = ref_by_desc(proc, tr->target.handle);
            if (!r) { err = BR_FAILED_REPLY; goto fail; }
            node = r->node;
        } else {
            node = proc->ctx->mgr;
            if (!node) { err = BR_DEAD_REPLY; goto fail; }
            if (node->proc == proc) { err = BR_FAILED_REPLY; goto fail; }
        }
        if (!node->proc || node->proc->dead) { err = BR_DEAD_REPLY; goto fail; }
        target = node->proc;
        if (!(tr->flags & TF_ONE_WAY) && thread->stack) {
            if (thread->stack->to_thread != thread) { err = BR_FAILED_REPLY; goto fail; }
            // A thread already in a call chain with the target handles the nested call, which
            // is what keeps call-backs from deadlocking.
            for (btxn *x = thread->stack; x; x = x->from_parent)
                if (x->from && x->from->proc == target) { target_thread = x->from; break; }
        }
    }

    // Data, offsets, scatter-gather buffers, then the security context.
    if (tr->offsets_size % 8 || extra % 8) { err = BR_FAILED_REPLY; goto fail; }
    bool secctx = !reply && (node->flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX);
    uint64_t ctxlen = secctx ? ALIGN8(sizeof SECCTX) : 0;
    uint64_t size = ALIGN8(tr->data_size) + ALIGN8(tr->offsets_size) + extra + ctxlen;
    if (size < tr->data_size || size > target->size) { err = BR_FAILED_REPLY; goto fail; }
    bbuf *b = buf_alloc(target, size);
    if (!b) { err = target->rw ? BR_FAILED_REPLY : BR_DEAD_REPLY; goto fail; }
    b->data_size = tr->data_size;
    b->offsets_size = tr->offsets_size;
    b->async = !reply && (tr->flags & TF_ONE_WAY);
    b->clear = tr->flags & TF_CLEAR_BUF;
    bool allow_fds = reply ? (in_reply_to->flags & TF_ACCEPT_FDS) : (node->flags & FLAT_BINDER_FLAG_ACCEPTS_FDS);
    uint64_t done = 0;
    err = translate(proc, thread, target, b, tr, extra, allow_fds, &done);
    if (err) {
        buf_release_objects(target, b, done);
        buf_free(target, b, false);
        goto fail;
    }

    btxn *t = calloc(1, sizeof *t);
    LIST_INIT(&t->w.entry);
    t->w.type = W_TRANSACTION;
    t->from = !reply && !(tr->flags & TF_ONE_WAY) ? thread : NULL;
    t->from_pid = proc->pid;
    t->to_proc = target;
    t->to_thread = target_thread;
    t->code = tr->code;
    t->flags = tr->flags;
    t->reply = reply;
    t->buf = b;
    b->txn = t;
    if (secctx) {
        uint64_t at = b->off + size - ctxlen;
        memcpy(target->rw + at, SECCTX, sizeof SECCTX);
        t->secctx = target->ubase + at;
    }
    if (node) {
        b->target = node;
        node_inc(node, true, false, NULL);
    }
    trace("%d:%d %s %s code %#x size %llu to %d", proc->pid, thread->tid, proc->ctx->name,
          reply ? "reply" : (tr->flags & TF_ONE_WAY) ? "oneway" : "call", tr->code,
          (unsigned long long)tr->data_size, target->pid);

    queue_return(thread, BR_TRANSACTION_COMPLETE);
    if (reply) {
        stack_pop(target_thread, in_reply_to);
        txn_free(in_reply_to);
        queue_thread(target_thread, &t->w);
    } else if (t->from) {
        t->from_parent = thread->stack;
        thread->stack = t;
        if (target_thread) queue_thread(target_thread, &t->w);
        else queue_proc(target, &t->w);
    } else if (node->has_async) {
        list_add_tail(&node->async_todo, &t->w.entry);
    } else {
        node->has_async = true;
        queue_proc(target, &t->w);
    }
    return;

fail:
    trace("%d:%d %s failed: %#x", proc->pid, thread->tid, reply ? "reply" : "transaction", err);
    if (in_reply_to) {
        queue_return(thread, BR_TRANSACTION_COMPLETE);
        send_failed_reply(in_reply_to, err);
    } else {
        queue_return(thread, err);
    }
}

// ---- threads and processes ---------------------------------------------------------------
static bthread *thread_get(bproc *p) {
    int tid = am_self->tid;
    list_for(e, &p->threads) {
        bthread *t = container_of(e, bthread, entry);
        if (t->tid == tid) return t;
    }
    bthread *t = calloc(1, sizeof *t);
    t->proc = p;
    t->tid = tid;
    t->need_return = true;
    LIST_INIT(&t->todo);
    LIST_INIT(&t->wait_entry);
    pthread_cond_init(&t->cond, NULL);
    list_add_tail(&p->threads, &t->entry);
    return t;
}

// Drops work that will never be read: sync transactions fail back to their senders.
static void release_work(list *todo) {
    list *e;
    while ((e = list_pop(todo))) {
        work *w = container_of(e, work, entry);
        switch (w->type) {
        case W_TRANSACTION: {
            btxn *t = container_of(w, btxn, w);
            if (t->from) send_failed_reply(t, BR_DEAD_REPLY);
            else {
                txn_drop_buf(t);
                txn_free(t);
            }
            break;
        }
        case W_RETURN: free(w); break;
        case W_DEAD_BINDER: case W_DEAD_BINDER_AND_CLEAR: case W_CLEAR_DEATH:
            free(container_of(w, bdeath, w));
            break;
        case W_NODE: break;   // lives in its node
        }
    }
}

// binder_thread_release: transactions this thread was handling fail back to their senders;
// replies to calls it made will find no one.
static void thread_release(bthread *t) {
    btxn *send_reply = NULL;
    for (btxn *x = t->stack; x;) {
        if (x->to_thread == t) {
            send_reply = x;
            x->to_thread = NULL;
            x = x->to_parent;
        } else {
            x->from = NULL;
            x = x->from_parent;
        }
    }
    t->stack = NULL;
    if (send_reply) send_failed_reply(send_reply, BR_DEAD_REPLY);
    release_work(&t->todo);
    list_del(&t->wait_entry);
    list_del(&t->entry);
    if (t->in_ioctl) {
        // Still blocked in a read on another host thread: it frees itself on the way out.
        t->proc = NULL;
        pthread_cond_signal(&t->cond);
        return;
    }
    pthread_cond_destroy(&t->cond);
    free(t);
}

static void proc_free(bproc *p) {
    close(p->pipe_w);
    if (p->rw) {
        munmap(p->rw, p->size);
        munmap((void *)p->ubase, p->size);
    }
    free(p);
}

// binder_deferred_release: the process closed its last binder fd (or died).
static void proc_release(bproc *p) {
    p->dead = true;
    if (p->ctx->mgr && p->ctx->mgr->proc == p) p->ctx->mgr = NULL;
    list *e;
    while (!list_empty(&p->threads)) thread_release(container_of(p->threads.next, bthread, entry));
    // Buffers first: they point at this proc's nodes, which go next.
    list_for(e, &p->bufs) {
        bbuf *b = container_of(e, bbuf, entry);
        b->target = NULL;
        buf_free(p, b, false);
    }
    while ((e = list_pop(&p->nodes))) {
        bnode *n = container_of(e, bnode, entry);
        list_del(&n->w.entry);
        release_work(&n->async_todo);
        if (list_empty(&n->refs)) { free(n); continue; }
        n->proc = NULL;
        n->local_strong = n->local_weak = 0;
        n->has_strong = n->has_weak = false;
        list_add_tail(&dead_nodes, &n->entry);
        list_for(re, &n->refs) {
            bref *r = container_of(re, bref, node_entry);
            if (r->proc != p && r->death && list_empty(&r->death->w.entry)) {
                r->death->w.type = W_DEAD_BINDER;
                queue_proc(r->proc, &r->death->w);
            }
        }
    }
    while (!list_empty(&p->refs)) ref_free(container_of(p->refs.next, bref, proc_entry));
    release_work(&p->todo);
    release_work(&p->delivered_death);
    trace("%d %s released", p->pid, p->ctx->name);
}

// ---- reading -----------------------------------------------------------------------------
#define PUT32(v) do { uint32_t _v = (v); memcpy(ptr, &_v, 4); ptr += 4; } while (0)
#define PUT(v) do { memcpy(ptr, &(v), sizeof(v)); ptr += sizeof(v); } while (0)

static void put_txn(bproc *p, bthread *thread, btxn *t, uint8_t **pp) {
    uint8_t *ptr = *pp;
    bbuf *b = t->buf;
    struct binder_transaction_data_secctx tr = {0};
    struct binder_transaction_data *d = &tr.transaction_data;
    if (b->target) {
        d->target.ptr = b->target->ptr;
        d->cookie = b->target->cookie;
    }
    d->code = t->code;
    d->flags = t->flags;
    d->sender_pid = t->from ? t->from_pid : 0;   // Linux reports 0 for oneway calls
    d->sender_euid = 0;
    d->data_size = b->data_size;
    d->offsets_size = b->offsets_size;
    d->data.ptr.buffer = p->ubase + b->off;
    d->data.ptr.offsets = p->ubase + b->off + ALIGN8(b->data_size);
    tr.secctx = t->secctx;
    // The receiver's fds go in now that it is reading, as Linux's deferred fd fixups do.
    for (int i = 0; i < b->nfix; i++) {
        long fd = am_fd_install(p->aproc, b->fix[i].f, 0, true);
        if (fd < 0) { am_file_put(b->fix[i].f); fd = -1; }
        uint32_t v = (uint32_t)fd;
        memcpy(p->rw + b->off + b->fix[i].off, &v, 4);
    }
    free(b->fix);
    b->fix = NULL;
    b->nfix = 0;
    b->user_free = true;
    if (t->reply) PUT32(BR_REPLY);
    else if (t->secctx) PUT32(BR_TRANSACTION_SEC_CTX);
    else PUT32(BR_TRANSACTION);
    memcpy(ptr, &tr, t->secctx ? sizeof tr : sizeof *d);
    ptr += t->secctx ? sizeof tr : sizeof *d;
    *pp = ptr;
    if (!t->reply && t->from) {
        t->to_parent = thread->stack;
        t->to_thread = thread;
        thread->stack = t;
    } else {
        txn_free(t);
    }
}

// binder_thread_read. Returns 0, or -EAGAIN for a nonblocking read with nothing to do.
static long thread_read(bproc *p, bthread *thread, uint8_t *buf, uint64_t size, uint64_t *consumed, bool nonblock) {
    uint8_t *ptr = buf + *consumed, *end = buf + size;
    if (*consumed == 0) {
        if (end - ptr < 4) return 0;
        PUT32(BR_NOOP);
    }
    long ret = 0;
    for (;;) {
        if (end - ptr < 4 + (long)sizeof(struct binder_transaction_data_secctx)) break;
        list *src = NULL;
        bool proc_ok = proc_work_ok(thread);
        if (!list_empty(&thread->todo)) src = &thread->todo;
        else if (proc_ok && !list_empty(&p->todo)) src = &p->todo;
        if (!src) {
            if (ptr - buf != 4 || *consumed != 0 || thread->need_return || p->dead) break;
            if (nonblock) return AM_ERR(LINUX_EAGAIN);   // read_consumed stays 0, as on Linux
            if (proc_ok) list_add_tail(&p->waiting, &thread->wait_entry);
            thread->waiting = true;
            poll_update(p);
            pthread_cond_wait(&thread->cond, &lock);
            thread->waiting = false;
            list_del(&thread->wait_entry);
            if (!thread->proc) break;   // released meanwhile
            continue;
        }
        work *w = container_of(list_pop(src), work, entry);
        switch (w->type) {
        case W_RETURN: {
            ret_work *r = (ret_work *)w;
            PUT32(r->cmd);
            if (r->cmd != BR_TRANSACTION_COMPLETE) thread->error_pending = false;
            free(r);
            continue;
        }
        case W_TRANSACTION:
            put_txn(p, thread, container_of(w, btxn, w), &ptr);
            goto done;
        case W_NODE: {
            bnode *n = container_of(w, bnode, w);
            bool strong = n->internal_strong || n->local_strong;
            bool weak = !list_empty(&n->refs) || n->local_weak || strong;
            bool had_strong = n->has_strong, had_weak = n->has_weak;
            struct binder_ptr_cookie pc = {n->ptr, n->cookie};
            if (weak && !had_weak) { n->has_weak = n->pending_weak = true; n->local_weak++; }
            if (strong && !had_strong) { n->has_strong = n->pending_strong = true; n->local_strong++; }
            if (!strong && had_strong) n->has_strong = false;
            if (!weak && had_weak) n->has_weak = false;
            if (weak && !had_weak) { PUT32(BR_INCREFS); PUT(pc); }
            if (strong && !had_strong) { PUT32(BR_ACQUIRE); PUT(pc); }
            if (!strong && had_strong) { PUT32(BR_RELEASE); PUT(pc); }
            if (!weak && had_weak) { PUT32(BR_DECREFS); PUT(pc); }
            if (!weak && !strong) node_free(n);
            continue;
        }
        case W_DEAD_BINDER: case W_DEAD_BINDER_AND_CLEAR: case W_CLEAR_DEATH: {
            bdeath *d = container_of(w, bdeath, w);
            bool clear = w->type == W_CLEAR_DEATH;
            PUT32(clear ? BR_CLEAR_DEATH_NOTIFICATION_DONE : BR_DEAD_BINDER);
            PUT(d->cookie);
            if (clear) { free(d); continue; }
            list_add_tail(&p->delivered_death, &d->w.entry);
            goto done;   // a death notification can cause transactions
        }
        }
    }
done:
    *consumed = ptr - buf;
    // Ask for another looper when none is idle and the pool is not full.
    if (!ret && thread->proc && !p->requested && list_empty(&p->waiting) && p->started < p->max_threads &&
        (thread->looper & (LOOPER_REGISTERED | LOOPER_ENTERED))) {
        p->requested++;
        uint32_t v = BR_SPAWN_LOOPER;
        memcpy(buf, &v, 4);
    }
    return ret;
}

// ---- writing -----------------------------------------------------------------------------
static long thread_write(bproc *p, bthread *thread, const uint8_t *buf, uint64_t size, uint64_t *consumed) {
    const uint8_t *ptr = buf + *consumed, *end = buf + size;
    while (ptr + 4 <= end && !thread->error_pending) {
        uint32_t cmd;
        memcpy(&cmd, ptr, 4);
        uint32_t len = LINUX_IOC_SIZE(cmd);
        if (ptr + 4 + len > end) return AM_ERR(LINUX_EFAULT);
        const uint8_t *arg = ptr + 4;
        switch (cmd) {
        case BC_TRANSACTION: case BC_REPLY: {
            struct binder_transaction_data tr;
            memcpy(&tr, arg, sizeof tr);
            transact(p, thread, &tr, cmd == BC_REPLY, 0);
            break;
        }
        case BC_TRANSACTION_SG: case BC_REPLY_SG: {
            struct binder_transaction_data_sg tr;
            memcpy(&tr, arg, sizeof tr);
            transact(p, thread, &tr.transaction_data, cmd == BC_REPLY_SG, tr.buffers_size);
            break;
        }
        case BC_INCREFS: case BC_ACQUIRE: case BC_RELEASE: case BC_DECREFS: {
            uint32_t desc;
            memcpy(&desc, arg, 4);
            ref_update(p, desc, cmd == BC_INCREFS || cmd == BC_ACQUIRE, cmd == BC_ACQUIRE || cmd == BC_RELEASE);
            break;
        }
        case BC_INCREFS_DONE: case BC_ACQUIRE_DONE: {
            struct binder_ptr_cookie pc;
            memcpy(&pc, arg, sizeof pc);
            bnode *n = node_get(p, pc.ptr);
            if (!n || n->cookie != pc.cookie) break;
            bool strong = cmd == BC_ACQUIRE_DONE;
            if (strong ? !n->pending_strong : !n->pending_weak) break;
            if (strong) n->pending_strong = false;
            else n->pending_weak = false;
            node_dec(n, strong, false);
            break;
        }
        case BC_FREE_BUFFER: {
            uint64_t ua;
            memcpy(&ua, arg, 8);
            bbuf *b = buf_find(p, ua);
            if (!b || !b->user_free) break;
            if (b->async && b->target) {
                bnode *n = b->target;
                list *next = list_pop(&n->async_todo);
                if (next) queue_proc(p, container_of(next, work, entry));
                else n->has_async = false;
            }
            buf_free(p, b, true);
            break;
        }
        case BC_REGISTER_LOOPER:
            if (p->requested) { p->requested--; p->started++; }
            thread->looper |= LOOPER_REGISTERED;
            break;
        case BC_ENTER_LOOPER: thread->looper |= LOOPER_ENTERED; break;
        case BC_EXIT_LOOPER: thread->looper |= LOOPER_EXITED; break;
        case BC_REQUEST_DEATH_NOTIFICATION: case BC_CLEAR_DEATH_NOTIFICATION: {
            struct binder_handle_cookie hc;
            memcpy(&hc, arg, sizeof hc);
            bref *r = ref_by_desc(p, hc.handle);
            if (!r) break;
            if (cmd == BC_REQUEST_DEATH_NOTIFICATION) {
                if (r->death) break;
                bdeath *d = calloc(1, sizeof *d);
                LIST_INIT(&d->w.entry);
                d->cookie = hc.cookie;
                r->death = d;
                if (!r->node->proc) {
                    d->w.type = W_DEAD_BINDER;
                    queue_self_or_proc(thread, &d->w);
                }
            } else {
                bdeath *d = r->death;
                if (!d || d->cookie != hc.cookie) break;
                r->death = NULL;
                if (list_empty(&d->w.entry)) {
                    d->w.type = W_CLEAR_DEATH;
                    queue_self_or_proc(thread, &d->w);
                } else {
                    d->w.type = W_DEAD_BINDER_AND_CLEAR;
                }
            }
            break;
        }
        case BC_DEAD_BINDER_DONE: {
            uint64_t cookie;
            memcpy(&cookie, arg, 8);
            list_for(e, &p->delivered_death) {
                bdeath *d = container_of(e, bdeath, w.entry);
                if (d->cookie != cookie) continue;
                list_del(&d->w.entry);
                if (d->w.type == W_DEAD_BINDER_AND_CLEAR) {
                    d->w.type = W_CLEAR_DEATH;
                    queue_self_or_proc(thread, &d->w);
                }   // else it stays on its ref, unqueued, until cleared
                break;
            }
            break;
        }
        case BC_ACQUIRE_RESULT: case BC_ATTEMPT_ACQUIRE:
        case BC_REQUEST_FREEZE_NOTIFICATION: case BC_CLEAR_FREEZE_NOTIFICATION: case BC_FREEZE_NOTIFICATION_DONE:
            break;
        default:
            return AM_ERR(LINUX_EINVAL);
        }
        ptr += 4 + len;
        *consumed = ptr - buf;
    }
    return 0;
}

// ---- file ops ----------------------------------------------------------------------------
static long set_context_mgr(bproc *p, const struct flat_binder_object *fbo) {
    if (p->ctx->mgr) return AM_ERR(LINUX_EBUSY);
    bnode *n = node_new(p, fbo ? fbo->binder : 0, fbo ? fbo->cookie : 0, fbo ? fbo->flags : 0);
    // The manager node is born referenced, so its owner never hears BR_INCREFS/BR_ACQUIRE.
    n->local_weak++;
    n->local_strong++;
    n->has_strong = n->has_weak = true;
    p->ctx->mgr = n;
    trace("%d becomes %s context manager", p->pid, p->ctx->name);
    return 0;
}

static long binder_ioctl(am_file *f, unsigned long req, uint64_t arg) {
    bproc *p = f->priv;
    long r = 0;
    pthread_mutex_lock(&lock);
    if (p->dead) { pthread_mutex_unlock(&lock); return AM_ERR(LINUX_EBADF); }
    bthread *t = thread_get(p);
    p->busy++;
    t->in_ioctl++;
    switch ((uint32_t)req) {
    case BINDER_WRITE_READ: {
        struct binder_write_read *bwr = (void *)arg;
        if (bwr->write_size > 0) {
            r = thread_write(p, t, (const uint8_t *)bwr->write_buffer, bwr->write_size, &bwr->write_consumed);
            if (r < 0) { bwr->read_consumed = 0; break; }
        }
        if (bwr->read_size > 0)
            r = thread_read(p, t, (uint8_t *)bwr->read_buffer, bwr->read_size, &bwr->read_consumed,
                            f->lflags & LINUX_O_NONBLOCK);
        break;
    }
    case BINDER_SET_MAX_THREADS: p->max_threads = *(uint32_t *)arg; break;
    case BINDER_SET_CONTEXT_MGR: r = set_context_mgr(p, NULL); break;
    case BINDER_SET_CONTEXT_MGR_EXT: r = set_context_mgr(p, (const struct flat_binder_object *)arg); break;
    case BINDER_THREAD_EXIT:
        t->in_ioctl--;
        thread_release(t);
        t = NULL;
        break;
    case BINDER_VERSION: ((struct binder_version *)arg)->protocol_version = BINDER_CURRENT_PROTOCOL_VERSION; break;
    case BINDER_GET_NODE_DEBUG_INFO: {
        // The node with the lowest ptr above the one given, so callers can walk all of them.
        struct binder_node_debug_info *di = (void *)arg;
        bnode *best = NULL;
        list_for(e, &p->nodes) {
            bnode *n = container_of(e, bnode, entry);
            if (n->ptr > di->ptr && (!best || n->ptr < best->ptr)) best = n;
        }
        memset(di, 0, sizeof *di);
        if (best) {
            di->ptr = best->ptr;
            di->cookie = best->cookie;
            di->has_strong_ref = best->has_strong;
            di->has_weak_ref = best->has_weak;
        }
        break;
    }
    case BINDER_GET_NODE_INFO_FOR_REF: {
        struct binder_node_info_for_ref *ni = (void *)arg;
        bref *rf = ref_by_desc(p, ni->handle);
        if (!p->ctx->mgr || p->ctx->mgr->proc != p) { r = AM_ERR(LINUX_EPERM); break; }
        if (!rf || ni->strong_count || ni->weak_count || ni->reserved1 || ni->reserved2 || ni->reserved3) {
            r = AM_ERR(LINUX_EINVAL);
            break;
        }
        bnode *n = rf->node;
        int nrefs = 0;
        list_for(e, &n->refs) nrefs++;
        ni->strong_count = n->internal_strong + n->local_strong;
        ni->weak_count = nrefs + n->local_weak;
        break;
    }
    case BINDER_GET_EXTENDED_ERROR: {
        struct binder_extended_error *ee = (void *)arg;
        ee->id = 0;
        ee->command = BR_OK;
        ee->param = 0;
        break;
    }
    case BINDER_GET_FROZEN_INFO: {
        struct binder_frozen_status_info *fi = (void *)arg;
        fi->sync_recv = fi->async_recv = 0;
        break;
    }
    case BINDER_ENABLE_ONEWAY_SPAM_DETECTION: case BINDER_FREEZE:
    case BINDER_SET_IDLE_TIMEOUT: case BINDER_SET_IDLE_PRIORITY:
        break;
    default: r = AM_ERR(LINUX_EINVAL); break;
    }
    if (t) {
        t->in_ioctl--;
        t->need_return = false;
        if (!t->proc) { pthread_cond_destroy(&t->cond); free(t); }   // released while we slept
    }
    p->busy--;
    if (!p->dead) poll_update(p);
    bool gone = p->dead && !p->busy;
    pthread_mutex_unlock(&lock);
    if (gone) proc_free(p);
    return r;
}

// The guest maps the fd read-only; the runtime keeps a writable alias of the same pages to
// copy transactions into.
static long binder_mmap(am_file *f, uint64_t addr, uint64_t len, int prot, int flags, uint64_t off) {
    bproc *p = f->priv;
    if (prot & LINUX_PROT_WRITE) return AM_ERR(LINUX_EPERM);
    if (len > MAX_MAP) len = MAX_MAP;
    len = (len + AM_PAGE - 1) & ~(uint64_t)(AM_PAGE - 1);
    pthread_mutex_lock(&lock);
    long r;
    if (p->rw) { r = AM_ERR(LINUX_EBUSY); goto out; }
    void *rw = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (rw == MAP_FAILED) { r = AM_ERR(LINUX_ENOMEM); goto out; }
    mach_vm_address_t g = (flags & LINUX_MAP_FIXED) ? addr : 0;
    vm_prot_t cur, max;
    kern_return_t kr = mach_vm_remap(mach_task_self(), &g, len, 0,
                                     (flags & LINUX_MAP_FIXED) ? VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE : VM_FLAGS_ANYWHERE,
                                     mach_task_self(), (mach_vm_address_t)rw, false, &cur, &max, VM_INHERIT_NONE);
    if (kr) { munmap(rw, len); r = AM_ERR(LINUX_ENOMEM); goto out; }
    mprotect((void *)g, len, PROT_READ);
    p->rw = rw;
    p->ubase = g;
    p->size = len;
    r = (long)g;
out:
    pthread_mutex_unlock(&lock);
    return r;
}

static void binder_release(am_file *f) {
    bproc *p = f->priv;
    pthread_mutex_lock(&lock);
    proc_release(p);
    bool gone = !p->busy;
    pthread_mutex_unlock(&lock);
    if (gone) proc_free(p);
}

static long binder_read(am_file *f, void *buf, size_t n) { return AM_ERR(LINUX_EINVAL); }
static long binder_write(am_file *f, const void *buf, size_t n) { return AM_ERR(LINUX_EINVAL); }

static const am_file_ops binder_ops = {
    .name = "binder",
    .read = binder_read,
    .write = binder_write,
    .ioctl = binder_ioctl,
    .mmap = binder_mmap,
    .release = binder_release,
};

static long binder_open(const char *name, int lflags, am_file **out) {
    bctx *ctx = NULL;
    for (int i = 0; i < 3; i++)
        if (!strcmp(name, contexts[i].name)) ctx = &contexts[i];
    if (!ctx) return AM_ERR(LINUX_ENOENT);
    int fds[2];
    if (pipe(fds)) return am_errno(errno);
    fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFL, O_NONBLOCK);
    if (lflags & LINUX_O_NONBLOCK) fcntl(fds[0], F_SETFL, O_NONBLOCK);
    bproc *p = calloc(1, sizeof *p);
    p->ctx = ctx;
    p->aproc = am_self->proc;
    p->pid = am_self->proc->pid;
    LIST_INIT(&p->threads);
    LIST_INIT(&p->nodes);
    LIST_INIT(&p->refs);
    LIST_INIT(&p->todo);
    LIST_INIT(&p->delivered_death);
    LIST_INIT(&p->waiting);
    LIST_INIT(&p->bufs);
    p->pipe_r = fds[0];
    p->pipe_w = fds[1];
    *out = am_file_new(fds[0], lflags, NULL, &binder_ops, p);
    trace("%d opens /dev/%s", p->pid, name);
    return 0;
}

void am_binder_init(void) {
    for (int i = 0; i < 3; i++) am_dev_register(contexts[i].name, binder_open);
}
