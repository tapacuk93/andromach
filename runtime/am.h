// andromach runtime: runs precompiled Android arm64 userland natively on Darwin (iOS, macOS),
// standing in for the Linux kernel underneath it.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>

// Shared with tools/amc.py.
#define AM_HEADER_SIZE 0x4000
#define AM_MARKER_OFF 0x3000
#define AM_MARKER "ANDROMACH-IMAGE"
#define AM_TSD_GUEST_TP 110
#define AM_TSD_ENTRY 111
#define AM_TSD_HOST_STACK 112   // runtime only: the top of the thread's host stack
#define AM_TRAP_SVC 0xA500
#define AM_TRAP_MRS_TP 0xA520
#define AM_TRAP_MSR_TP 0xA540
#define AM_TRAP_RESUME 0xA5FF // host only: x0 points at the am_ctx to install

#define AM_PAGE 0x4000

// A guest thread's registers, as the stub entry and the trap handler capture them. The offsets
// are used by entry.S.
typedef struct am_ctx {
    uint64_t x[31];
    uint64_t sp, pc, pstate;  // 248, 256, 264
    __uint128_t v[32];        // 272
    uint32_t fpsr, fpcr;      // 784, 788
    uint64_t pad;
} am_ctx;
_Static_assert(sizeof(am_ctx) == 800, "entry.S frame");

// ---- open files --------------------------------------------------------------------------
// Every open file has a host fd when it can: poll, epoll and readiness then work on the host
// fd. Files the runtime implements itself (sockets, eventfd, binder, ...) add ops; any op left
// NULL falls back to the host fd.
typedef struct am_file am_file;
struct iovec;
typedef struct am_file_ops {
    const char *name;
    long (*read)(am_file *f, void *buf, size_t n);
    long (*write)(am_file *f, const void *buf, size_t n);
    long (*ioctl)(am_file *f, unsigned long req, uint64_t arg);
    long (*mmap)(am_file *f, uint64_t addr, uint64_t len, int prot, int flags, uint64_t off);
    void (*release)(am_file *f);   // last reference gone; the host fd is closed after it
    // Whole-vector I/O, for files where one readv/writev is one message (datagram sockets).
    long (*readv)(am_file *f, const struct iovec *iov, int n);
    long (*writev)(am_file *f, const struct iovec *iov, int n);
} am_file_ops;

// A device under /dev the runtime implements: open returns 0 and fills *out, or -errno.
typedef long (*am_dev_open_fn)(const char *name, int lflags, am_file **out);
void am_dev_register(const char *name, am_dev_open_fn open);

struct am_file {
    int refs;
    int hostfd;
    const am_file_ops *ops;
    void *priv;
    int lflags;          // Linux open flags
    bool image;          // a precompiled image: the guest sees [base, base + size)
    uint64_t base, size;
    uint64_t pos;        // our own offset, used for images
    char *gpath;         // guest path it was opened by (for *at() and /proc/self/fd)
    // getdents64 state
    void *dents; size_t dents_len, dents_pos;
};

#define AM_MAX_FDS 1024

typedef struct am_sigaction { uint64_t handler, flags, restorer, mask; } am_sigaction;

// A guest memory range, recorded so a process's memory can be snapshotted at fork, released
// at exit and listed in /proc/self/maps.
typedef struct am_vma { uint64_t start, end; bool shared; } am_vma;

typedef struct am_thread am_thread;
typedef struct am_fork am_fork;

typedef struct am_proc {
    int pid, ppid, pgid, sid;
    pthread_mutex_t lock;          // fds, threads
    am_file *fds[AM_MAX_FDS];
    uint8_t cloexec[AM_MAX_FDS];
    char cwd[1024];
    char exe[1024];
    char *cmdline;                 // argv, NUL-separated, for /proc/<pid>/cmdline
    size_t cmdline_len;
    am_sigaction sig[65];
    uint64_t sigpending;           // process-directed signals not yet taken by a thread
    uint32_t umask;
    pthread_mutex_t vm_lock;
    am_vma *vmas;
    int nvma, vma_cap;
    am_thread *threads;            // list through am_thread.next
    int nthreads;
    // lifecycle, under the process table lock
    int state;                     // AM_PROC_*
    int exit_status;               // wait status: exit code << 8, or the signal
    bool exiting;
} am_proc;

enum { AM_PROC_RUNNING, AM_PROC_ZOMBIE, AM_PROC_REAPED };

struct am_thread {
    am_proc *proc;
    am_thread *next;
    int tid;
    uint64_t sigmask;
    uint64_t sigpending;
    uint64_t clear_child_tid;
    uint64_t altstack[3];          // Linux stack_t: ss_sp, ss_flags (+pad), ss_size
    pthread_t host;
    void *host_stack;              // runs exit and exec, once the guest stack may be gone
    void *host_stack_top;
    volatile int in_runtime;       // inside a system call: asynchronous signals wait for its end
    volatile bool killed;          // asked to exit (exit_group, exec, fatal signal)
    am_fork *fork;                 // set while this thread is a fork child running in its parent's memory
    uint32_t wake;                 // futex word: bumped when a signal is queued
};

extern __thread am_thread *am_self;
extern const char *am_root;      // host directory holding the guest's read-only root
extern const char *am_datadir;   // host directory for writable guest paths (/data, /tmp, ...)
extern int am_strace;
extern bool am_deny_exec;        // refuse executable mappings that are not image files (iOS rule)

// entry.S
void am_syscall_entry(void);
__attribute__((noreturn)) void am_resume(const am_ctx *c);
void am_call_on_host_stack(void (*fn)(void *), void *arg);  // returns; for system calls from traps

// trap.c
void am_trap_init(void);
void am_thread_tsd_init(uint64_t guest_tp);   // also points the host-stack slot at am_self's

// sys.c
void am_syscall(am_ctx *c, int from_trap);
long am_errno(int darwin_errno);
#define AM_ERR(e) (-(long)(e))

// fs.c
void am_fs_init(am_proc *p);
void am_fs_register_devices(void);
int am_resolve(int dirfd, const char *gpath, bool follow, char *host, size_t hostsz, char *canon, size_t canonsz);
long am_open(const char *gpath, int dirfd, int lflags, int mode, am_file **out);
int am_fd_install(am_proc *p, am_file *f, int min, bool cloexec);
am_file *am_fd_get(int fd);
void am_file_put(am_file *f);
long am_pread(am_file *f, void *buf, size_t n, uint64_t off);
long sys_fs(am_ctx *c, long nr, bool *handled);
am_file *am_file_new(int hostfd, int lflags, const char *gpath, const am_file_ops *ops, void *priv);

// procfs.c
long am_procfs_open(const char *canon, int lflags, am_file **out);

// mm.c
long am_mmap(uint64_t addr, uint64_t len, int prot, int flags, int fd, uint64_t off);
long sys_mm(am_ctx *c, long nr, bool *handled);
void am_vma_add(am_proc *p, uint64_t start, uint64_t end, bool shared);
void am_vma_remove(am_proc *p, uint64_t start, uint64_t end);
void am_vma_unmap_all(am_proc *p);

// thread.c
long sys_thread(am_ctx *c, long nr, bool *handled);
am_thread *am_thread_new(am_proc *p, int tid);
void am_thread_free(am_thread *t);
int am_new_tid(void);
int am_thread_start(am_thread *t, const am_ctx *c, uint64_t tls);
__attribute__((noreturn)) void am_run_on_host_stack(void (*fn)(void *), void *arg);
__attribute__((noreturn)) void am_thread_exit(void);
long am_futex_wake(uint32_t *addr, int n);
long am_futex_wait_interruptible(uint32_t *addr, uint32_t val);  // returns on wake, kick or 50 ms
void am_thread_exit_tail(void *thread);

// proc.c
am_proc *am_proc_new(am_proc *parent);
am_proc *am_proc_get(int pid);
void am_fork_munmap(uint64_t start, uint64_t end);                 // NULL if no such live process
void am_proc_for_each(void (*fn)(am_proc *, void *), void *arg);
long sys_proc(am_ctx *c, long nr, bool *handled, int from_trap);
__attribute__((noreturn)) void am_proc_exit(int status);   // the calling thread's process
extern int am_init_pid;                        // the first process; its exit ends the host

// signal.c
void am_signal_init(void);
long sys_signal(am_ctx *c, long nr, bool *handled, int from_trap);
long am_kill_proc(am_proc *p, int sig, int code, int from_pid);
long am_kill_thread(am_thread *t, int sig, int code, int from_pid);
bool am_signal_deliver(am_ctx *c);             // sets c up to run a pending handler; true if it did
bool am_signal_fault(int sig, int code, uint64_t addr, am_ctx *c);  // a guest fault: true if the guest handles it
void am_ctx_from_mc(am_ctx *c, const void *mcontext);
void am_ctx_to_mc(void *mcontext, const am_ctx *c);

// net.c, event.c, binder.c
long sys_net(am_ctx *c, long nr, bool *handled);
long sys_event(am_ctx *c, long nr, bool *handled);
void am_event_file_gone(am_file *f);      // drops f from every epoll set; called before release
void am_event_hostfd_changed(am_file *f); // f->hostfd now names another host object
bool am_sock_peer_gone(am_file *f);       // for EPOLLHUP: the other end is closed
void am_binder_init(void);

// loader.c
long am_exec(am_ctx *c, const char *gpath, char *const argv[], char *const envp[]);
