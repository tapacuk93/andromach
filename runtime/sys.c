// The system call dispatcher, plus the calls that fit nowhere else: identity, time, limits,
// signal bookkeeping.
#include "am.h"
#include "linux.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

long am_errno(int e) {
    static const short map[][2] = {
        {EAGAIN, 11}, {EDEADLK, 35}, {ENAMETOOLONG, 36}, {ENOLCK, 37}, {ENOSYS, 38},
        {ENOTEMPTY, 39}, {ELOOP, 40}, {ENOMSG, 42}, {EIDRM, 43}, {ENOSTR, 60}, {ENODATA, 61},
        {ETIME, 62}, {ENOSR, 63}, {ENOLINK, 67}, {EPROTO, 71}, {EMULTIHOP, 72}, {EBADMSG, 74},
        {EOVERFLOW, 75}, {EILSEQ, 84}, {EUSERS, 87}, {ENOTSOCK, 88}, {EDESTADDRREQ, 89},
        {EMSGSIZE, 90}, {EPROTOTYPE, 91}, {ENOPROTOOPT, 92}, {EPROTONOSUPPORT, 93},
        {ESOCKTNOSUPPORT, 94}, {EOPNOTSUPP, 95}, {ENOTSUP, 95}, {EPFNOSUPPORT, 96},
        {EAFNOSUPPORT, 97}, {EADDRINUSE, 98}, {EADDRNOTAVAIL, 99}, {ENETDOWN, 100},
        {ENETUNREACH, 101}, {ENETRESET, 102}, {ECONNABORTED, 103}, {ECONNRESET, 104},
        {ENOBUFS, 105}, {EISCONN, 106}, {ENOTCONN, 107}, {ESHUTDOWN, 108}, {ETOOMANYREFS, 109},
        {ETIMEDOUT, 110}, {ECONNREFUSED, 111}, {EHOSTDOWN, 112}, {EHOSTUNREACH, 113},
        {EALREADY, 114}, {EINPROGRESS, 115}, {ESTALE, 116}, {EDQUOT, 122}, {ECANCELED, 125},
        {EOWNERDEAD, 130}, {ENOTRECOVERABLE, 131},
    };
    for (size_t i = 0; i < sizeof map / sizeof *map; i++)
        if (map[i][0] == e) return -map[i][1];
    return -(long)e;  // 1..34 are the same on both
}

static int linux_clock(int id) {
    switch (id) {
    case 0: case 5: case 8: return CLOCK_REALTIME;           // REALTIME, _COARSE, _ALARM
    case 1: case 6: return CLOCK_UPTIME_RAW;                  // MONOTONIC: stops in sleep
    case 4: return CLOCK_MONOTONIC_RAW;
    case 7: case 9: return CLOCK_MONOTONIC;                   // BOOTTIME: counts sleep
    case 2: return CLOCK_PROCESS_CPUTIME_ID;
    case 3: return CLOCK_THREAD_CPUTIME_ID;
    }
    return -1;
}

static long sys_misc(am_ctx *c, long nr, bool *handled) {
#define A(i) (c->x[i])
    *handled = true;
    am_proc *p = am_self->proc;
    switch (nr) {
    case LINUX_SYS_getuid: case LINUX_SYS_geteuid: case LINUX_SYS_getgid: case LINUX_SYS_getegid:
        return 0;  // the guest runs as root: it is alone in its sandbox
    case LINUX_SYS_getresuid: case LINUX_SYS_getresgid:
        *(uint32_t *)A(0) = *(uint32_t *)A(1) = *(uint32_t *)A(2) = 0;
        return 0;
    case LINUX_SYS_setuid: case LINUX_SYS_setgid: case LINUX_SYS_setreuid: case LINUX_SYS_setregid:
    case LINUX_SYS_setresuid: case LINUX_SYS_setresgid: case LINUX_SYS_setgroups:
    case LINUX_SYS_setfsuid: case LINUX_SYS_setfsgid: case LINUX_SYS_capset:
        return 0;
    case LINUX_SYS_getgroups: return 0;
    case LINUX_SYS_capget: {
        uint32_t *data = (void *)A(1);
        if (data) memset(data, 0xFF, 24);
        return 0;
    }
    case LINUX_SYS_getpgid: case LINUX_SYS_getsid: return p->pid;
    case LINUX_SYS_setpgid: return 0;
    case LINUX_SYS_setsid: return p->pid;
    case LINUX_SYS_uname: {
        struct linux_utsname *u = (void *)A(0);
        memset(u, 0, sizeof *u);
        strcpy(u->sysname, "Linux");
        strcpy(u->nodename, "localhost");
        strcpy(u->release, "6.6.0-andromach");
        strcpy(u->version, "#1 SMP PREEMPT");
        strcpy(u->machine, "aarch64");
        strcpy(u->domainname, "(none)");
        return 0;
    }
    case LINUX_SYS_sethostname: return 0;
    case LINUX_SYS_clock_gettime: case LINUX_SYS_clock_getres: {
        int id = linux_clock((int)A(0));
        if (id < 0) return AM_ERR(LINUX_EINVAL);
        struct timespec ts;
        if ((nr == LINUX_SYS_clock_gettime ? clock_gettime : clock_getres)(id, &ts)) return am_errno(errno);
        if (A(1)) *(struct linux_timespec *)A(1) = (struct linux_timespec){ts.tv_sec, ts.tv_nsec};
        return 0;
    }
    case LINUX_SYS_gettimeofday: {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        if (A(0)) { int64_t *tv = (void *)A(0); tv[0] = ts.tv_sec; tv[1] = ts.tv_nsec / 1000; }
        if (A(1)) memset((void *)A(1), 0, 8);
        return 0;
    }
    case LINUX_SYS_nanosleep: case LINUX_SYS_clock_nanosleep: {
        const struct linux_timespec *req = (void *)(nr == LINUX_SYS_nanosleep ? A(0) : A(2));
        struct timespec ts = {req->tv_sec, req->tv_nsec};
        if (nr == LINUX_SYS_clock_nanosleep && (A(1) & 1)) {  // TIMER_ABSTIME
            struct timespec now;
            clock_gettime(linux_clock((int)A(0)), &now);
            int64_t ns = (ts.tv_sec - now.tv_sec) * 1000000000ll + (ts.tv_nsec - now.tv_nsec);
            if (ns <= 0) return 0;
            ts.tv_sec = ns / 1000000000; ts.tv_nsec = ns % 1000000000;
        }
        return nanosleep(&ts, NULL) ? am_errno(errno) : 0;
    }
    case LINUX_SYS_getrandom: arc4random_buf((void *)A(0), A(1)); return A(1);
    case LINUX_SYS_sched_yield: sched_yield(); return 0;
    case LINUX_SYS_sched_getaffinity: {
        int n = 0;
        size_t sz = sizeof n;
        sysctlbyname("hw.ncpu", &n, &sz, NULL, 0);
        size_t bytes = A(1) < 8 ? A(1) : 8;
        uint64_t mask = n >= 64 ? ~0ull : (1ull << n) - 1;
        memcpy((void *)A(2), &mask, bytes);
        return bytes;
    }
    case LINUX_SYS_sched_setaffinity: case LINUX_SYS_sched_setscheduler: return 0;
    case LINUX_SYS_sched_getscheduler: return 0;
    case LINUX_SYS_sched_getparam: *(int *)A(1) = 0; return 0;
    case LINUX_SYS_getpriority: return 20;
    case LINUX_SYS_setpriority: return 0;
    case LINUX_SYS_getcpu:
        if (A(0)) *(uint32_t *)A(0) = 0;
        if (A(1)) *(uint32_t *)A(1) = 0;
        return 0;
    case LINUX_SYS_getrlimit: case LINUX_SYS_setrlimit: case LINUX_SYS_prlimit64: {
        int res = (int)(nr == LINUX_SYS_prlimit64 ? A(1) : A(0));
        struct linux_rlimit *old = (void *)(nr == LINUX_SYS_prlimit64 ? A(3) : nr == LINUX_SYS_getrlimit ? A(1) : 0);
        if (old) {
            old->cur = old->max = ~0ull;
            if (res == 3) old->cur = 8 << 20;         // RLIMIT_STACK
            if (res == 7) old->cur = old->max = AM_MAX_FDS;  // RLIMIT_NOFILE
        }
        return 0;
    }
    case LINUX_SYS_getrusage: {
        memset((void *)A(1), 0, 144);
        return 0;
    }
    case LINUX_SYS_times: return (long)(clock() / (CLOCKS_PER_SEC / 100));
    case LINUX_SYS_sysinfo: {
        struct linux_sysinfo *s = (void *)A(0);
        memset(s, 0, sizeof *s);
        uint64_t mem = 0;
        size_t sz = sizeof mem;
        sysctlbyname("hw.memsize", &mem, &sz, NULL, 0);
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        s->uptime = ts.tv_sec;
        s->totalram = mem;
        s->freeram = mem / 2;
        s->procs = 1;
        s->mem_unit = 1;
        return 0;
    }
    case LINUX_SYS_prctl:
        switch (A(0)) {
        case 15: /* PR_SET_NAME */ pthread_setname_np((const char *)A(1)); return 0;
        case 16: /* PR_GET_NAME */ pthread_getname_np(pthread_self(), (char *)A(1), 16); return 0;
        case 0x53564d41: /* PR_SET_VMA */ return 0;
        case 55: /* PR_SET_TAGGED_ADDR_CTRL */ return AM_ERR(LINUX_EINVAL);
        case 56: /* PR_GET_TAGGED_ADDR_CTRL */ return AM_ERR(LINUX_EINVAL);
        }
        return 0;
    case LINUX_SYS_membarrier: return A(0) == 0 ? 0 : 0;
    case LINUX_SYS_rseq: return AM_ERR(LINUX_ENOSYS);
    case LINUX_SYS_fadvise64: return 0;

    // Signals: recorded so the guest sees consistent answers. Delivery comes later.
    case LINUX_SYS_rt_sigaction: {
        int sig = (int)A(0);
        if (sig < 1 || sig > 64) return AM_ERR(LINUX_EINVAL);
        if (A(2)) *(am_sigaction *)A(2) = p->sig[sig];
        if (A(1)) {
            if (sig == 9 || sig == 19) return AM_ERR(LINUX_EINVAL);
            p->sig[sig] = *(am_sigaction *)A(1);
        }
        return 0;
    }
    case LINUX_SYS_rt_sigprocmask: {
        uint64_t old = am_self->sigmask;
        if (A(1)) {
            uint64_t set = *(uint64_t *)A(1);
            if (A(0) == 0) am_self->sigmask |= set;
            else if (A(0) == 1) am_self->sigmask &= ~set;
            else am_self->sigmask = set;
            am_self->sigmask &= ~((1ull << 8) | (1ull << 18));  // SIGKILL, SIGSTOP
        }
        if (A(2)) *(uint64_t *)A(2) = old;
        return 0;
    }
    case LINUX_SYS_sigaltstack:
        if (A(1)) memcpy((void *)A(1), am_self->altstack, 24);
        if (A(0)) memcpy(am_self->altstack, (void *)A(0), 24);
        return 0;
    case LINUX_SYS_rt_sigpending: memset((void *)A(0), 0, 8); return 0;
    case LINUX_SYS_kill: case LINUX_SYS_tgkill: case LINUX_SYS_tkill: {
        int sig = (int)(nr == LINUX_SYS_tgkill ? A(2) : A(1));
        if (sig == 0) return 0;
        fprintf(stderr, "andromach: signal %d sent; delivery is not implemented yet\n", sig);
        if (sig == 6 || sig == 9 || sig == 15) { fflush(NULL); _exit(128 + sig); }
        return 0;
    }
    }
    *handled = false;
    return 0;
#undef A
}

static const char *const names[] = {
#define N(x) [LINUX_SYS_##x] = #x
    N(getcwd), N(dup), N(dup3), N(fcntl), N(ioctl), N(mkdirat), N(unlinkat), N(symlinkat),
    N(renameat), N(statfs), N(fstatfs), N(ftruncate), N(faccessat), N(chdir), N(fchdir),
    N(openat), N(close), N(pipe2), N(getdents64), N(lseek), N(read), N(write), N(readv),
    N(writev), N(pread64), N(pwrite64), N(ppoll), N(readlinkat), N(newfstatat), N(fstat),
    N(exit), N(exit_group), N(set_tid_address), N(futex), N(set_robust_list), N(nanosleep),
    N(clock_gettime), N(sched_yield), N(kill), N(tgkill), N(sigaltstack), N(rt_sigaction),
    N(rt_sigprocmask), N(rt_sigreturn), N(uname), N(getrlimit), N(umask), N(prctl),
    N(gettimeofday), N(getpid), N(getppid), N(getuid), N(geteuid), N(gettid), N(socket),
    N(connect), N(brk), N(munmap), N(mremap), N(clone), N(execve), N(mmap), N(mprotect),
    N(madvise), N(wait4), N(prlimit64), N(getrandom), N(memfd_create), N(statx), N(clone3),
    N(faccessat2), N(sched_getaffinity), N(sysinfo), N(epoll_create1), N(eventfd2),
#undef N
};

void am_syscall(am_ctx *c) {
    long nr = (long)c->x[8];
    bool handled = false;
    long r = sys_fs(c, nr, &handled);
    if (!handled) r = sys_mm(c, nr, &handled);
    if (!handled) r = sys_thread(c, nr, &handled);
    if (!handled) r = sys_misc(c, nr, &handled);
    if (!handled) r = sys_net(c, nr, &handled);
    if (!handled) r = sys_event(c, nr, &handled);
    if (!handled) {
        if (am_strace || nr != LINUX_SYS_rseq) {
            const char *n = nr >= 0 && nr < (long)(sizeof names / sizeof *names) ? names[nr] : NULL;
            fprintf(stderr, "andromach: unimplemented syscall %ld%s%s%s\n", nr, n ? " (" : "", n ? n : "", n ? ")" : "");
        }
        r = AM_ERR(LINUX_ENOSYS);
    }
    if (am_strace) {
        const char *n = nr >= 0 && nr < (long)(sizeof names / sizeof *names) ? names[nr] : NULL;
        char buf[32];
        if (!n) { snprintf(buf, sizeof buf, "sys_%ld", nr); n = buf; }
        if (nr == LINUX_SYS_openat || nr == LINUX_SYS_newfstatat || nr == LINUX_SYS_readlinkat || nr == LINUX_SYS_faccessat)
            fprintf(stderr, "[%d] %s(%lld, \"%s\", %#llx) = %ld\n", am_self->tid, n, (long long)c->x[0], (char *)c->x[1],
                    (unsigned long long)c->x[2], r);
        else
            fprintf(stderr, "[%d] %s(%#llx, %#llx, %#llx, %#llx) = %#lx\n", am_self->tid, n, (unsigned long long)c->x[0],
                    (unsigned long long)c->x[1], (unsigned long long)c->x[2], (unsigned long long)c->x[3], r);
    }
    c->x[0] = (uint64_t)r;
}
