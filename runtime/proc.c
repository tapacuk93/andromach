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
// The parent of a vfork child waits until it execs or exits; their memory is one.
static void vfork_done(am_proc *p) {
    am_thread *w = p->vfork_parent;
    if (!w) return;
    p->vfork_parent = NULL;
    __atomic_store_n(&w->vfork_wait, 0, __ATOMIC_SEQ_CST);
    am_futex_wake(&w->vfork_wait, 1);
}

static long sys_fork(am_ctx *c, uint64_t flags, uint64_t newsp, uint64_t ptid, uint64_t ctid) {
    am_thread *pt = am_self;
    am_proc *pp = pt->proc;
    am_proc *cp = am_proc_new(pp);
    am_thread *ct = am_thread_new(cp, cp->pid);  // the main thread's tid is the pid
    ct->sigmask = pt->sigmask;
    memcpy(ct->altstack, pt->altstack, sizeof ct->altstack);
    bool shared = flags & LINUX_CLONE_VM;
    if (shared) cp->vfork_shared = true;
    else am_mg_fork(pp, cp);  // the child's pages: the parent's, as they are now
    if (flags & LINUX_CLONE_PARENT_SETTID) *(int *)ptid = cp->pid;
    if (flags & LINUX_CLONE_CHILD_SETTID) ct->start_settid = ctid;
    if (flags & LINUX_CLONE_CHILD_CLEARTID) ct->clear_child_tid = ctid;
    am_ctx child = *c;
    child.x[0] = 0;
    if (newsp) child.sp = newsp;
    uint64_t *tsd;
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(tsd));
    if (shared && (flags & LINUX_CLONE_VFORK)) {
        pt->vfork_wait = 1;
        cp->vfork_parent = pt;
    }
    if (am_thread_start(ct, &child, tsd[AM_TSD_GUEST_TP])) return AM_ERR(LINUX_EAGAIN);
    if (cp->vfork_parent) {
        am_block_begin();
        while (__atomic_load_n(&pt->vfork_wait, __ATOMIC_SEQ_CST))
            am_futex_wait_interruptible(&pt->vfork_wait, 1);
        am_block_end();
    }
    return cp->pid;
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

// Programs whose job the build has already done, or that need what a sandbox cannot give.
// apexd mounts APEX images through loop devices and dm-verity; the APEXes are unpacked into the
// root at build time, so it only has to report them active, as the properties init waits for.
static bool stand_in(const char *path, char ***argv) {
    char canon[1024];
    if (am_resolve(LINUX_AT_FDCWD, path, true, NULL, 0, canon, sizeof canon) < 0) return false;
    const char *script = NULL;
    if (!strcmp(canon, "/system/bin/apexd")) {
        bool service = !(*argv)[1];
        script = service ? "setprop apexd.status activated; setprop apexd.status ready; "
                           "exec sleep 2147483647"
                         : "exit 0";  // --bootstrap, --unmount-all, --snapshotde, ...
    }
    if (!script) return false;
    free_strv(*argv);
    char **nv = calloc(4, sizeof *nv);
    nv[0] = strdup("/system/bin/sh");
    nv[1] = strdup("-c");
    nv[2] = strdup(script);
    *argv = nv;
    return true;
}

static long sys_execve(const char *gpath, char *const *gargv, char *const *genvp) {
    // crash_dump attaches to the crashed process with ptrace, which there is no way to offer;
    // refusing it lets bionic's crash handler fall back to its own short report.
    if (strstr(gpath, "/crash_dump")) return AM_ERR(LINUX_ENOENT);
    am_thread *t = am_self;
    am_proc *p = t->proc;
    char *path = strdup(gpath);
    char **argv = copy_strv(gargv), **envp = copy_strv(genvp);
    if (stand_in(path, &argv)) {
        free(path);
        path = strdup(argv[0]);
    }
    for (int depth = 0; depth < 4 && script_argv(path, &argv); depth++) {
        free(path);
        path = strdup(argv[0]);
    }

    // Other threads go away first, as Linux kills them at exec.
    {
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

    if (p->mg || p->vfork_shared) {
        // The old memory is not ours alone: a group's ranges stay for the others, a vfork
        // parent keeps all of it. Only our own allocations go.
        if (p->mg) am_mg_leave(p, old, nold);
        free(old);
        old = NULL;
        nold = 0;
        p->vfork_shared = false;
        vfork_done(p);
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
    if (t->clear_child_tid) {
        __atomic_store_n((uint32_t *)t->clear_child_tid, 0, __ATOMIC_SEQ_CST);
        am_futex_wake((uint32_t *)t->clear_child_tid, 1);
    }
    if (p->mg || p->vfork_shared) {
        // As at exec: release only what is ours alone.
        pthread_mutex_lock(&p->vm_lock);
        am_vma *old = p->vmas;
        int nold = p->nvma;
        p->vmas = NULL;
        p->nvma = p->vma_cap = 0;
        pthread_mutex_unlock(&p->vm_lock);
        if (p->mg) am_mg_leave(p, old, nold);
        free(old);
        p->vfork_shared = false;
        vfork_done(p);
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
static am_proc *wait_child_locked(int idtype, int id, int options, long *err);

static am_proc *wait_child(int idtype, int id, int options, long *err) {
    if (!(options & 1)) am_block_begin();  // writes no guest memory while it waits
    am_proc *r = wait_child_locked(idtype, id, options, err);
    if (!(options & 1)) am_block_end();
    return r;
}

static am_proc *wait_child_locked(int idtype, int id, int options, long *err) {
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
        return sys_fork(c, A(0), A(1), A(2), A(4));
    case LINUX_SYS_clone3: {
        struct { uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls; } *a = (void *)A(0);
        if (a->flags & LINUX_CLONE_THREAD) break;
        return sys_fork(c, a->flags, a->stack ? a->stack + a->stack_size : 0, a->parent_tid, a->child_tid);
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
