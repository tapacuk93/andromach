// Memory groups: fork without exec, in one address space.
//
// A forked child and its parent want different contents at the same addresses. Here they take
// turns: a memory group holds every process forked from a common ancestor that has not exec'd
// yet. One member at a time is resident, with its private pages installed. Every other
// member's pages are kept as copy-on-write copies at other addresses. Switching members swaps
// those copies in and out, which costs one remap per range, not per page.
//
// Residency is held by every thread that runs guest code or touches guest memory, like a
// lock. A thread lets go of it only where it waits: in a blocking read, poll, wait4, futex,
// sleep or sigsuspend (am_block_begin/end). A member that wants to run kicks the resident's
// threads. Those running guest code park in the kick handler, and those in a system call
// yield when it ends. So parent and child both run, one at a time, and a child blocked on a
// pipe lets its parent fill it: all that init's services, shells and the like need.
#include "am.h"
#include "linux.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

struct am_mgroup {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    am_proc *resident;   // whose pages are installed; NULL once it left (they are garbage then)
    int holders;         // threads of the resident member holding residency
    int wanted;          // threads of other members waiting for it
    int members;
    am_proc *procs[64];  // the members
    am_vma *regions;     // the ranges whose contents differ between members
    int nregions, cap;
};

struct am_mg_copy { uint64_t addr, size, copy; int prot; };

// Whether a belongs to the group's ranges or to a member other than self; *end is where that
// stretch ends.
static bool kept(am_mgroup *g, am_proc *self, uint64_t a, uint64_t *end) {
    for (int i = 0; i < g->nregions; i++)
        if (a >= g->regions[i].start && a < g->regions[i].end) { *end = g->regions[i].end; return true; }
    for (int m = 0; m < g->members; m++) {
        am_proc *o = g->procs[m];
        if (o == self) continue;
        bool hit = false;
        pthread_mutex_lock(&o->vm_lock);
        for (int i = 0; i < o->nvma; i++)
            if (a >= o->vmas[i].start && a < o->vmas[i].end) { *end = o->vmas[i].end; hit = true; break; }
        pthread_mutex_unlock(&o->vm_lock);
        if (hit) return true;
    }
    return false;
}

// Adds p's private, non-executable ranges to the group's set.
static void add_regions(am_mgroup *g, am_proc *p) {
    pthread_mutex_lock(&p->vm_lock);
    for (int i = 0; i < p->nvma; i++) {
        am_vma *v = &p->vmas[i];
        if (v->shared) continue;
        bool dup = false;
        for (int j = 0; j < g->nregions; j++)
            if (g->regions[j].start == v->start && g->regions[j].end == v->end) { dup = true; break; }
        if (dup) continue;
        if (g->nregions == g->cap) g->regions = realloc(g->regions, (g->cap = g->cap ? g->cap * 2 : 64) * sizeof *g->regions);
        g->regions[g->nregions++] = *v;
    }
    pthread_mutex_unlock(&p->vm_lock);
}

// Copy-on-write copies of the group's ranges as they are now, one per kernel map entry so each
// keeps its protection. Code is skipped: it is the same for every member.
static void save(am_mgroup *g, am_proc *p) {
    int cap = 64, n = 0;
    struct am_mg_copy *c = malloc(cap * sizeof *c);
    for (int i = 0; i < g->nregions; i++) {
        mach_vm_address_t a = g->regions[i].start, end = g->regions[i].end;
        while (a < end) {
            mach_vm_address_t r = a;
            mach_vm_size_t sz;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj;
            if (mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj))
                break;
            if (r >= end) break;
            uint64_t s0 = r > a ? r : a, e0 = r + sz < end ? r + sz : end;
            a = e0;
            if (info.protection & VM_PROT_EXECUTE) continue;
            mach_vm_address_t copy = 0;
            vm_prot_t cur, max;
            if (mach_vm_remap(mach_task_self(), &copy, e0 - s0, 0, VM_FLAGS_ANYWHERE, mach_task_self(), s0, TRUE,
                              &cur, &max, VM_INHERIT_NONE) != KERN_SUCCESS)
                continue;
            if (n == cap) c = realloc(c, (cap *= 2) * sizeof *c);
            c[n++] = (struct am_mg_copy){s0, e0 - s0, copy, info.protection};
        }
    }
    p->mg_saved = c;
    p->mg_nsaved = n;
}

static void install(am_proc *p) {
    for (int i = 0; i < p->mg_nsaved; i++) {
        struct am_mg_copy *s = &p->mg_saved[i];
        mach_vm_address_t to = s->addr;
        vm_prot_t cur, max;
        mach_vm_remap(mach_task_self(), &to, s->size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(), s->copy,
                      FALSE, &cur, &max, VM_INHERIT_DEFAULT);
        mach_vm_protect(mach_task_self(), s->addr, s->size, FALSE, s->prot);
        mach_vm_deallocate(mach_task_self(), s->copy, s->size);
    }
    free(p->mg_saved);
    p->mg_saved = NULL;
    p->mg_nsaved = 0;
}

static void discard(am_proc *p) {
    for (int i = 0; i < p->mg_nsaved; i++) mach_vm_deallocate(mach_task_self(), p->mg_saved[i].copy, p->mg_saved[i].size);
    free(p->mg_saved);
    p->mg_saved = NULL;
    p->mg_nsaved = 0;
}

static void kick_resident(am_mgroup *g) {
    am_proc *r = g->resident;
    if (!r) return;
    pthread_mutex_lock(&r->lock);
    for (am_thread *t = r->threads; t; t = t->next)
        if (t->mg_holds && !t->in_runtime && t->host) pthread_kill(t->host, SIGUSR2);
    pthread_mutex_unlock(&r->lock);
}

void am_mg_acquire(void) {
    am_thread *t = am_self;
    am_mgroup *g = t->proc->mg;
    if (!g || t->mg_holds) return;
    am_proc *p = t->proc;
    pthread_mutex_lock(&g->lock);
    while (g->resident != p && g->resident && g->holders > 0) {
        g->wanted++;
        kick_resident(g);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 5 * 1000000;
        if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
        pthread_cond_timedwait(&g->cond, &g->lock, &ts);
        g->wanted--;
    }
    if (g->resident != p) {
        if (g->resident) save(g, g->resident);
        install(p);
        g->resident = p;
    }
    g->holders++;
    t->mg_holds = true;
    pthread_mutex_unlock(&g->lock);
}

void am_mg_release(void) {
    am_thread *t = am_self;
    am_mgroup *g = t->proc->mg;
    if (!g || !t->mg_holds) return;
    pthread_mutex_lock(&g->lock);
    t->mg_holds = false;
    if (--g->holders == 0) pthread_cond_broadcast(&g->cond);
    pthread_mutex_unlock(&g->lock);
}

void am_block_begin(void) {
    am_self->in_block = true;
    am_mg_release();
}

void am_block_end(void) {
    am_self->in_block = false;
    am_mg_acquire();
}

// At the end of a system call, and in the kick handler for a thread in guest code: let a
// waiting member have its turn.
void am_mg_yield(void) {
    am_thread *t = am_self;
    am_mgroup *g = t->proc->mg;
    if (!g) return;
    if (!t->mg_holds) { am_mg_acquire(); return; }
    if (!__atomic_load_n(&g->wanted, __ATOMIC_RELAXED)) return;
    am_mg_release();
    // Give the waiter time to take it before competing again.
    struct timespec ts = {0, 100000};
    nanosleep(&ts, NULL);
    am_mg_acquire();
}

bool am_mg_wanted(void) {
    am_mgroup *g = am_self->proc->mg;
    return g && am_self->mg_holds && __atomic_load_n(&g->wanted, __ATOMIC_RELAXED);
}

// fork: puts parent and child in one group (creating it), the child's pages saved as they are now.
void am_mg_fork(am_proc *parent, am_proc *child) {
    am_mgroup *g = parent->mg;
    if (!g) {
        g = calloc(1, sizeof *g);
        pthread_mutex_init(&g->lock, NULL);
        pthread_cond_init(&g->cond, NULL);
        g->members = 1;
        g->procs[0] = parent;
        g->resident = parent;
        // Threads running guest code or inside a system call hold residency from now on;
        // those waiting will take it when their wait ends.
        pthread_mutex_lock(&parent->lock);
        for (am_thread *t = parent->threads; t; t = t->next)
            if (!t->in_block) { t->mg_holds = true; g->holders++; }
        pthread_mutex_unlock(&parent->lock);
        parent->mg = g;
    }
    pthread_mutex_lock(&g->lock);
    add_regions(g, parent);
    save(g, child);
    child->mg = g;
    if (g->members < 64) g->procs[g->members++] = child;
    pthread_mutex_unlock(&g->lock);
}

// Unmaps [start, end) for a group member, except what the group or another member still uses:
// the group's ranges stay mapped for the other members' contents, and inherited mappings are
// the others' too.
void am_mg_munmap(uint64_t start, uint64_t end) {
    am_proc *self = am_self->proc;
    am_mgroup *g = self->mg;
    pthread_mutex_lock(&g->lock);
    uint64_t a = start;
    while (a < end) {
        uint64_t kend;
        if (kept(g, self, a, &kend)) { a = kend; continue; }
        uint64_t b = a + AM_PAGE;
        while (b < end && !kept(g, self, b, &kend)) b += AM_PAGE;
        if (b > end) b = end;
        munmap((void *)a, b - a);
        a = b;
    }
    pthread_mutex_unlock(&g->lock);
}

// p leaves its group (exec or exit). Its own allocations go; the rest stays.
void am_mg_leave(am_proc *p, am_vma *old, int nold) {
    am_mgroup *g = p->mg;
    if (!g) return;
    for (int i = 0; i < nold; i++) am_mg_munmap(old[i].start, old[i].end);
    pthread_mutex_lock(&g->lock);
    pthread_mutex_lock(&p->lock);
    for (am_thread *t = p->threads; t; t = t->next)
        if (t->mg_holds) { t->mg_holds = false; g->holders--; }
    pthread_mutex_unlock(&p->lock);
    if (g->resident == p) g->resident = NULL;
    else discard(p);
    for (int m = 0; m < g->members; m++)
        if (g->procs[m] == p) { g->procs[m] = g->procs[--g->members]; break; }
    p->mg = NULL;
    pthread_cond_broadcast(&g->cond);
    pthread_mutex_unlock(&g->lock);
}
