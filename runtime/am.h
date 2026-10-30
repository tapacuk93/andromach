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
typedef struct am_file_ops {
    const char *name;
    long (*read)(am_file *f, void *buf, size_t n);
    long (*write)(am_file *f, const void *buf, size_t n);
    long (*ioctl)(am_file *f, unsigned long req, uint64_t arg);
    long (*mmap)(am_file *f, uint64_t addr, uint64_t len, int prot, int flags, uint64_t off);
    void (*release)(am_file *f);   // last reference gone; the host fd is closed after it
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

typedef struct am_proc {
    int pid, ppid;
    pthread_mutex_t lock;
    am_file *fds[AM_MAX_FDS];
    uint8_t cloexec[AM_MAX_FDS];
    char cwd[1024];
    char exe[1024];
    am_sigaction sig[65];
    uint32_t umask;
} am_proc;

typedef struct am_thread {
    am_proc *proc;
    int tid;
    uint64_t sigmask;
    uint64_t clear_child_tid;
    uint64_t altstack[3];
    pthread_t host;
    void *host_stack_top;    // where the exit path runs once the guest stack may be gone
} am_thread;

extern __thread am_thread *am_self;
extern const char *am_root;      // host directory holding the guest's read-only root
extern const char *am_datadir;   // host directory for writable guest paths (/data, /tmp, ...)
extern int am_strace;
extern bool am_deny_exec;        // refuse executable mappings that are not image files (iOS rule)

// entry.S
void am_syscall_entry(void);
__attribute__((noreturn)) void am_resume(const am_ctx *c);

// trap.c
void am_trap_init(void);
void am_thread_tsd_init(uint64_t guest_tp);

// sys.c
void am_syscall(am_ctx *c);
long am_errno(int darwin_errno);
#define AM_ERR(e) (-(long)(e))

// fs.c
void am_fs_init(am_proc *p);
int am_resolve(int dirfd, const char *gpath, bool follow, char *host, size_t hostsz, char *canon, size_t canonsz);
long am_open(const char *gpath, int dirfd, int lflags, int mode, am_file **out);
int am_fd_install(am_proc *p, am_file *f, int min, bool cloexec);
am_file *am_fd_get(int fd);
void am_file_put(am_file *f);
long am_pread(am_file *f, void *buf, size_t n, uint64_t off);
long sys_fs(am_ctx *c, long nr, bool *handled);
am_file *am_file_new(int hostfd, int lflags, const char *gpath, const am_file_ops *ops, void *priv);

// mm.c
long am_mmap(uint64_t addr, uint64_t len, int prot, int flags, int fd, uint64_t off);
long sys_mm(am_ctx *c, long nr, bool *handled);

// thread.c
long sys_thread(am_ctx *c, long nr, bool *handled);
am_thread *am_thread_new(am_proc *p, int tid);
int am_new_tid(void);

// net.c, event.c, binder.c
long sys_net(am_ctx *c, long nr, bool *handled);
long sys_event(am_ctx *c, long nr, bool *handled);
void am_binder_init(void);

// loader.c
long am_exec(am_ctx *c, const char *gpath, char *const argv[], char *const envp[]);
