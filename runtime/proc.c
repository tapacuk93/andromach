// Processes. iOS has no fork, so every guest process lives in this one host process, each with
// its own fd table, signal state and memory ranges.
//
// fork: the child runs first, on the parent's host thread and in the parent's memory, while the
// parent waits. The parent's private memory is snapshotted copy-on-write at the fork, so the
// child's writes are its own. When the child calls execve, its new program starts on a new
// host thread in fresh memory. When it exits, the snapshot is put back and the parent resumes
// with the child's pid. That is fork's meaning for the common case of fork-then-exec or
// fork-then-exit. A child that runs alongside its parent for a long time without exec is not
// modelled: the parent waits until it does one or the other.
//
// vfork and clone(CLONE_VM | CLONE_VFORK) (posix_spawn) are the same without the snapshot, which
// is exactly their meaning.
#include "am.h"
#include "linux.h"
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

int am_init_pid;

static pthread_mutex_t ptab_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ptab_cond = PTHREAD_COND_INITIALIZER;
static am_proc **ptab;
static int nptab, ptab_cap;

am_proc *am_proc_new(am_proc *parent) {
    am_proc *p = calloc(1, sizeof *p);
    pthread_mutex_init(&p->lock, NULL);
    pthread_mutex_init(&p->vm_lock, NULL);
    p->pid = am_new_tid();
    if (parent) {
        p->ppid = parent->pid;
        p->pgid = parent->pgid;
        p->sid = parent->sid;
        p->umask = parent->umask;
        memcpy(p->cwd, parent->cwd, sizeof p->cwd);
        memcpy(p->exe, parent->exe, sizeof p->exe);
        if (parent->cmdline) {
            p->cmdline = malloc(parent->cmdline_len);
            memcpy(p->cmdline, parent->cmdline, parent->cmdline_len);
            p->cmdline_len = parent->cmdline_len;
        }
        memcpy(p->sig, parent->sig, sizeof p->sig);
        pthread_mutex_lock(&parent->lock);
        for (int i = 0; i < AM_MAX_FDS; i++)
            if (parent->fds[i]) {
                p->fds[i] = parent->fds[i];
                __atomic_add_fetch(&p->fds[i]->refs, 1, __ATOMIC_ACQ_REL);
                p->cloexec[i] = parent->cloexec[i];
            }
        pthread_mutex_unlock(&parent->lock);
        pthread_mutex_lock(&parent->vm_lock);
        p->vma_cap = parent->nvma + 1;
        p->vmas = malloc(p->vma_cap * sizeof *p->vmas);
        memcpy(p->vmas, parent->vmas, parent->nvma * sizeof *p->vmas);
        p->nvma = parent->nvma;
        pthread_mutex_unlock(&parent->vm_lock);
    } else {
        p->ppid = 0;
        p->pgid = p->sid = p->pid;
        am_fs_init(p);
    }
    pthread_mutex_lock(&ptab_lock);
    if (nptab == ptab_cap) ptab = realloc(ptab, (ptab_cap = ptab_cap ? ptab_cap * 2 : 64) * sizeof *ptab);
    ptab[nptab++] = p;
    pthread_mutex_unlock(&ptab_lock);
    return p;
}

am_proc *am_proc_get(int pid) {
    am_proc *r = NULL;
    pthread_mutex_lock(&ptab_lock);
    for (int i = 0; i < nptab; i++)
        if (ptab[i]->pid == pid && ptab[i]->state == AM_PROC_RUNNING) r = ptab[i];
    pthread_mutex_unlock(&ptab_lock);
    return r;
}

void am_proc_for_each(void (*fn)(am_proc *, void *), void *arg) {
    pthread_mutex_lock(&ptab_lock);
    int n = nptab;
    am_proc *list[n ? n : 1];
    int k = 0;
    for (int i = 0; i < n; i++) if (ptab[i]->state == AM_PROC_RUNNING) list[k++] = ptab[i];
    pthread_mutex_unlock(&ptab_lock);
    for (int i = 0; i < k; i++) fn(list[i], arg);
}

static void close_all_fds(am_proc *p, bool only_cloexec) {
    for (int i = 0; i < AM_MAX_FDS; i++) {
        pthread_mutex_lock(&p->lock);
        am_file *f = p->fds[i];
        if (f && (!only_cloexec || p->cloexec[i])) p->fds[i] = NULL;
        else f = NULL;
        pthread_mutex_unlock(&p->lock);
        if (f) am_file_put(f);
    }
}

// ---- fork --------------------------------------------------------------------------------
typedef struct { uint64_t addr, size, copy; int prot; } snapshot;

struct am_fork {
    am_thread *parent;
    am_ctx ctx;               // the parent's state at the fork; resumed with x0 = child pid
    uint64_t tp;              // the parent's guest thread pointer
    uint64_t parent_tid_ptr;  // CLONE_PARENT_SETTID, written once the parent's memory is back
    snapshot *snaps;
    int nsnaps;
    am_vma *old;              // the child's ranges from before its exec, released at the end
    int nold;
    am_thread *exec_thread;   // the child's new program, started once the parent's memory is back
    am_ctx exec_ctx;
};

static void snapshot_memory(am_proc *p, am_fork *fk) {
    pthread_mutex_lock(&p->vm_lock);
    int cap = 64;
    fk->snaps = calloc(cap, sizeof *fk->snaps);
    for (int i = 0; i < p->nvma; i++) {
        am_vma *v = &p->vmas[i];
        if (v->shared) continue;
        // One copy per kernel map entry, so each keeps its own protection (RELRO next to data).
        mach_vm_address_t a = v->start;
        while (a < v->end) {
            mach_vm_address_t r = a;
            mach_vm_size_t sz;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj;
            if (mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj))
                break;
            if (r >= v->end) break;
            uint64_t s0 = r > a ? r : a, e0 = r + sz < v->end ? r + sz : v->end;
            a = e0;
            if (info.protection & VM_PROT_EXECUTE) continue;  // code never changes
            mach_vm_address_t copy = 0;
            vm_prot_t cur, max;
            // Copy-on-write: nothing is duplicated until one side writes.
            if (mach_vm_remap(mach_task_self(), &copy, e0 - s0, 0, VM_FLAGS_ANYWHERE, mach_task_self(), s0, TRUE,
                              &cur, &max, VM_INHERIT_NONE) != KERN_SUCCESS)
                continue;
            if (fk->nsnaps == cap) fk->snaps = realloc(fk->snaps, (cap *= 2) * sizeof *fk->snaps);
            fk->snaps[fk->nsnaps++] = (snapshot){s0, e0 - s0, copy, info.protection};
            if (getenv("AM_DEBUG")) fprintf(stderr, "snap %#llx-%#llx prot %d -> copy %#llx\n", (unsigned long long)s0,
                                            (unsigned long long)e0, info.protection, (unsigned long long)copy);
        }
    }
    pthread_mutex_unlock(&p->vm_lock);
}

static void restore_memory(am_fork *fk) {
    for (int i = 0; i < fk->nsnaps; i++) {
        snapshot *s = &fk->snaps[i];
        mach_vm_address_t to = s->addr;
        vm_prot_t cur, max;
        mach_vm_remap(mach_task_self(), &to, s->size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(),
                      s->copy, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
        mach_vm_protect(mach_task_self(), s->addr, s->size, FALSE, s->prot);
        mach_vm_deallocate(mach_task_self(), s->copy, s->size);
    }
    free(fk->snaps);
}

// Unmaps [start, end) for a fork child, except what belongs to the parent: those pages must
// stay where they are until the parent gets them back, or a new mapping could take their place.
void am_fork_munmap(uint64_t start, uint64_t end) {
    am_proc *parent = am_self->fork->parent->proc;
    pthread_mutex_lock(&parent->vm_lock);
    uint64_t cur = start;
    for (int j = 0; j < parent->nvma && cur < end; j++) {
        am_vma *v = &parent->vmas[j];
        if (v->end <= cur || v->start >= end) continue;
        if (v->start > cur) munmap((void *)cur, v->start - cur);
        cur = v->end;
    }
    if (cur < end) munmap((void *)cur, end - cur);
    pthread_mutex_unlock(&parent->vm_lock);
}

// Ranges in the child's list that the parent does not own: the child's own allocations.
static void release_child_ranges(am_vma *old, int nold) {
    for (int i = 0; i < nold; i++) am_fork_munmap(old[i].start, old[i].end);
    free(old);
}

// The fork child is done with its parent's memory (it exec'd or exited): give it back and
// resume the parent. Runs on the host stack.
static void fork_return(void *arg) {
    am_thread *child = arg;
    am_fork *fk = child->fork;
    am_proc *cp = child->proc;
    am_thread *parent = fk->parent;
    if (fk->old) release_child_ranges(fk->old, fk->nold);
    restore_memory(fk);
    // Only now may the child's new program run: until the restore is done its mappings could be
    // given addresses the restore is about to write.
    if (fk->exec_thread && am_thread_start(fk->exec_thread, &fk->exec_ctx, 0))
        fprintf(stderr, "andromach: cannot start pid %d\n", cp->pid);
    am_ctx c = fk->ctx;
    c.x[0] = cp->pid;
    if (fk->parent_tid_ptr) *(int *)fk->parent_tid_ptr = cp->pid;
    am_self = parent;
    am_thread_tsd_init(fk->tp);
    free(fk);
    child->fork = NULL;
    am_resume(&c);
}

static long sys_fork(am_ctx *c, uint64_t flags, uint64_t newsp, uint64_t ptid, uint64_t ctid, int from_trap) {
    am_thread *pt = am_self;
    am_proc *pp = pt->proc;
    am_proc *cp = am_proc_new(pp);
    am_thread *ct = am_thread_new(cp, cp->pid);  // the main thread's tid is the pid
    ct->sigmask = pt->sigmask;
    ct->host = pthread_self();
    memcpy(ct->altstack, pt->altstack, sizeof ct->altstack);
    am_fork *fk = calloc(1, sizeof *fk);
    fk->parent = pt;
    fk->ctx = *c;
    uint64_t *tsd;
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(tsd));
    fk->tp = tsd[AM_TSD_GUEST_TP];
    if (flags & LINUX_CLONE_PARENT_SETTID) fk->parent_tid_ptr = ptid;
    if (!(flags & LINUX_CLONE_VM)) snapshot_memory(pp, fk);
    ct->fork = fk;
    // The child's writes land in what is now its memory.
    if (flags & LINUX_CLONE_CHILD_SETTID) *(int *)ctid = cp->pid;
    if (flags & LINUX_CLONE_CHILD_CLEARTID) ct->clear_child_tid = ctid;
    am_self = ct;
    am_thread_tsd_init(fk->tp);  // the child's host stack from here on
    if (newsp) {
        c->sp = newsp;
        c->x[0] = 0;
        if (!from_trap) am_resume(c);
    }
    return 0;
}

// ---- exec --------------------------------------------------------------------------------
static char **copy_strv(char *const *v) {
    int n = 0;
    while (v && v[n]) n++;
    char **out = calloc(n + 1, sizeof *out);
    for (int i = 0; i < n; i++) out[i] = strdup(v[i]);
    return out;
}

static void free_strv(char **v) {
    for (int i = 0; v && v[i]; i++) free(v[i]);
    free(v);
}

// "#!interp [arg]": rewrites argv to run the interpreter on the script. 0 if not a script.
static int script_argv(const char *path, char ***argv) {
    am_file *f;
    if (am_open(path, LINUX_AT_FDCWD, LINUX_O_RDONLY, 0, &f) < 0) return 0;
    char line[256] = {0};
    long n = am_pread(f, line, sizeof line - 1, 0);
    am_file_put(f);
    if (n < 3 || line[0] != '#' || line[1] != '!') return 0;
    char *nl = strchr(line, '\n');
    if (nl) *nl = 0;
    char *interp = line + 2;
    while (*interp == ' ' || *interp == '\t') interp++;
    char *arg = interp;
    while (*arg && *arg != ' ' && *arg != '\t') arg++;
    if (*arg) { *arg++ = 0; while (*arg == ' ' || *arg == '\t') arg++; }
    int argc = 0;
    while ((*argv)[argc]) argc++;
    char **nv = calloc(argc + 3, sizeof *nv);
    int k = 0;
    nv[k++] = strdup(interp);
    if (*arg) nv[k++] = strdup(arg);
    nv[k++] = strdup(path);
    for (int i = 1; i < argc; i++) nv[k++] = (*argv)[i];
    free((*argv)[0]);
    free(*argv);
    *argv = nv;
    return 1;
}

typedef struct { am_vma *old; int nold; am_ctx ctx; } exec_tail_arg;

// A process that is not a fork child replaces its own image: release the old memory from the
// host stack, then start the new program on this same thread.
static void exec_tail(void *arg) {
    exec_tail_arg *a = arg;
    for (int i = 0; i < a->nold; i++) munmap((void *)a->old[i].start, a->old[i].end - a->old[i].start);
    free(a->old);
    am_ctx c = a->ctx;
    free(a);
    am_thread_tsd_init(0);
    am_resume(&c);
}

static long sys_execve(const char *gpath, char *const *gargv, char *const *genvp) {
    // crash_dump attaches to the crashed process with ptrace, which there is no way to offer;
    // refusing it lets bionic's crash handler fall back to its own short report.
    if (strstr(gpath, "/crash_dump")) return AM_ERR(LINUX_ENOENT);
    am_thread *t = am_self;
    am_proc *p = t->proc;
    char *path = strdup(gpath);
    char **argv = copy_strv(gargv), **envp = copy_strv(genvp);
    for (int depth = 0; depth < 4 && script_argv(path, &argv); depth++) {
        free(path);
        path = strdup(argv[0]);
    }

    // Other threads go away first, as Linux kills them at exec.
    if (!t->fork) {
        pthread_mutex_lock(&p->lock);
        for (am_thread *o = p->threads; o; o = o->next)
            if (o != t) { o->killed = true; pthread_kill(o->host, SIGUSR2); }
        pthread_mutex_unlock(&p->lock);
        for (int i = 0; i < 200 && p->nthreads > 1; i++) usleep(1000);
    }

    // Load into a fresh range list, keeping the old one until the new program is in place.
    pthread_mutex_lock(&p->vm_lock);
    am_vma *old = p->vmas;
    int nold = p->nvma;
    p->vmas = NULL;
    p->nvma = p->vma_cap = 0;
    pthread_mutex_unlock(&p->vm_lock);
    am_ctx nc;
    long r = am_exec(&nc, path, argv, envp);
    free(path);
    free_strv(argv);
    free_strv(envp);
    if (r < 0) {
        am_vma_unmap_all(p);  // whatever the failed load mapped
        pthread_mutex_lock(&p->vm_lock);
        free(p->vmas);
        p->vmas = old;
        p->nvma = p->vma_cap = nold;
        pthread_mutex_unlock(&p->vm_lock);
        return r;
    }
    close_all_fds(p, true);
    for (int s = 1; s <= 64; s++)
        if (p->sig[s].handler > 1) p->sig[s] = (am_sigaction){0};
    t->altstack[0] = t->altstack[2] = 0;
    t->altstack[1] = 2;
    t->clear_child_tid = 0;

    if (t->fork) {
        // The new program gets its own host thread; this one goes back to the parent.
        am_thread *nt = am_thread_new(p, p->pid);
        nt->sigmask = t->sigmask;
        nt->altstack[1] = 2;
        pthread_mutex_lock(&p->lock);
        for (am_thread **pp = &p->threads; *pp; pp = &(*pp)->next)
            if (*pp == t) { *pp = t->next; p->nthreads--; break; }
        pthread_mutex_unlock(&p->lock);
        t->fork->old = old;
        t->fork->nold = nold;
        t->fork->exec_thread = nt;
        t->fork->exec_ctx = nc;
        am_run_on_host_stack(fork_return, t);
    }
    exec_tail_arg *a = malloc(sizeof *a);
    a->old = old;
    a->nold = nold;
    a->ctx = nc;
    am_run_on_host_stack(exec_tail, a);
}

// ---- exit and wait -----------------------------------------------------------------------
static void become_zombie(am_proc *p, int status) {
    pthread_mutex_lock(&ptab_lock);
    p->state = AM_PROC_ZOMBIE;
    p->exit_status = status;
    // Orphans go to the first process, as they would to init.
    for (int i = 0; i < nptab; i++)
        if (ptab[i]->ppid == p->pid) ptab[i]->ppid = am_init_pid;
    pthread_cond_broadcast(&ptab_cond);
    pthread_mutex_unlock(&ptab_lock);
    am_proc *parent = am_proc_get(p->ppid);
    if (parent) am_kill_proc(parent, 17 /* SIGCHLD */, 0, p->pid);
}

typedef struct { am_proc *p; int status; } exit_arg;

static void exit_tail(void *arg) {
    exit_arg a = *(exit_arg *)arg;
    free(arg);
    am_proc *p = a.p;
    for (int i = 0; i < 1000 && p->nthreads > 1; i++) usleep(1000);  // the others are on their way out
    am_vma_unmap_all(p);
    become_zombie(p, a.status);
    if (p->pid == am_init_pid) {
        fflush(NULL);
        _exit(a.status & 0x7F ? 128 + (a.status & 0x7F) : (a.status >> 8) & 0xFF);
    }
    am_self = NULL;
    pthread_exit(NULL);
}

// status: exit code << 8, or a signal number for death by signal.
void am_proc_exit(int status) {
    am_thread *t = am_self;
    am_proc *p = t->proc;
    pthread_mutex_lock(&p->lock);
    if (p->exiting && p->exit_status && !(status & 0x7F)) status = p->exit_status;  // killed meanwhile
    p->exiting = true;
    for (am_thread *o = p->threads; o; o = o->next)
        if (o != t) { o->killed = true; if (o->host) pthread_kill(o->host, SIGUSR2); }
    pthread_mutex_unlock(&p->lock);
    close_all_fds(p, false);
    if (t->clear_child_tid && !t->fork) {
        __atomic_store_n((uint32_t *)t->clear_child_tid, 0, __ATOMIC_SEQ_CST);
        am_futex_wake((uint32_t *)t->clear_child_tid, 1);
    }
    if (t->fork) {
        // A fork child that never exec'd: its memory was the parent's.
        pthread_mutex_lock(&p->vm_lock);
        t->fork->old = p->vmas;
        t->fork->nold = p->nvma;
        p->vmas = NULL;
        p->nvma = p->vma_cap = 0;
        pthread_mutex_unlock(&p->vm_lock);
        p->nthreads = 0;
        p->threads = NULL;
        become_zombie(p, status);
        am_run_on_host_stack(fork_return, t);
    }
    exit_arg *a = malloc(sizeof *a);
    a->p = p;
    a->status = status;
    am_run_on_host_stack(exit_tail, a);
}

static bool wait_match(am_proc *self, am_proc *c, int idtype, int id) {
    if (c->ppid != self->pid) return false;
    switch (idtype) {
    case 0: return true;               // any child
    case 1: return c->pid == id;       // that pid
    case 2: return c->pgid == id;      // that process group
    }
    return false;
}

// Waits for a child to end. Returns the reaped child (still allocated) or NULL with *err set.
static am_proc *wait_child(int idtype, int id, int options, long *err) {
    am_proc *self = am_self->proc;
    pthread_mutex_lock(&ptab_lock);
    for (;;) {
        bool any = false;
        for (int i = 0; i < nptab; i++) {
            am_proc *c = ptab[i];
            if (c->state == AM_PROC_REAPED || !wait_match(self, c, idtype, id)) continue;
            any = true;
            if (c->state == AM_PROC_ZOMBIE) {
                if (!(options & 0x01000000)) c->state = AM_PROC_REAPED;  // WNOWAIT keeps it
                pthread_mutex_unlock(&ptab_lock);
                return c;
            }
        }
        if (!any) { *err = AM_ERR(LINUX_ECHILD); break; }
        if (options & 1) { *err = 0; break; }  // WNOHANG
        if (am_self->killed || ((am_self->sigpending | self->sigpending) & ~am_self->sigmask & ~(1ull << 16))) {
            *err = AM_ERR(LINUX_EINTR);
            break;
        }
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 20 * 1000000;
        if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
        pthread_cond_timedwait(&ptab_cond, &ptab_lock, &ts);
    }
    pthread_mutex_unlock(&ptab_lock);
    return NULL;
}

#define A(i) (c->x[i])

long sys_proc(am_ctx *c, long nr, bool *handled, int from_trap) {
    *handled = true;
    am_proc *p = am_self->proc;
    switch (nr) {
    case LINUX_SYS_clone:
        if (A(0) & LINUX_CLONE_THREAD) break;
        return sys_fork(c, A(0), A(1), A(2), A(4), from_trap);
    case LINUX_SYS_clone3: {
        struct { uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls; } *a = (void *)A(0);
        if (a->flags & LINUX_CLONE_THREAD) break;
        return sys_fork(c, a->flags, a->stack ? a->stack + a->stack_size : 0, a->parent_tid, a->child_tid, from_trap);
    }
    case LINUX_SYS_execve: return sys_execve((const char *)A(0), (char *const *)A(1), (char *const *)A(2));
    case 281: /* execveat */ {
        if (A(0) != (uint64_t)LINUX_AT_FDCWD && ((const char *)A(1))[0] != '/') return AM_ERR(LINUX_ENOSYS);
        return sys_execve((const char *)A(1), (char *const *)A(2), (char *const *)A(3));
    }
    case LINUX_SYS_exit_group: am_proc_exit(((int)A(0) & 0xFF) << 8);
    case LINUX_SYS_wait4: {
        int pid = (int)A(0);
        int idtype = pid == -1 ? 0 : pid > 0 ? 1 : 2;
        int id = pid > 0 ? pid : pid == 0 ? p->pgid : -pid;
        long err;
        am_proc *ch = wait_child(idtype, id, (int)A(2), &err);
        if (!ch) return err;
        if (A(1)) *(int *)A(1) = ch->exit_status;
        if (A(3)) memset((void *)A(3), 0, 144);
        return ch->pid;
    }
    case LINUX_SYS_waitid: {
        long err;
        am_proc *ch = wait_child((int)A(0), (int)A(1), (int)A(3), &err);
        int32_t *si = (int32_t *)A(2);
        if (!ch) {
            if (err == 0 && si) memset(si, 0, 128);
            return err;
        }
        if (si) {
            memset(si, 0, 128);
            si[0] = 17;                                     // SIGCHLD
            bool sig = ch->exit_status & 0x7F;
            si[2] = sig ? 2 : 1;                            // CLD_KILLED, CLD_EXITED
            si[4] = ch->pid;
            si[6] = sig ? ch->exit_status & 0x7F : (ch->exit_status >> 8) & 0xFF;
        }
        return 0;
    }
    case LINUX_SYS_getpgid: {
        am_proc *q = A(0) ? am_proc_get((int)A(0)) : p;
        return q ? q->pgid : AM_ERR(LINUX_ESRCH);
    }
    case LINUX_SYS_setpgid: {
        am_proc *q = A(0) ? am_proc_get((int)A(0)) : p;
        if (!q) return AM_ERR(LINUX_ESRCH);
        q->pgid = A(1) ? (int)A(1) : q->pid;
        return 0;
    }
    case LINUX_SYS_getsid: {
        am_proc *q = A(0) ? am_proc_get((int)A(0)) : p;
        return q ? q->sid : AM_ERR(LINUX_ESRCH);
    }
    case LINUX_SYS_setsid:
        p->sid = p->pgid = p->pid;
        return p->sid;
    }
    *handled = false;
    return 0;
}
