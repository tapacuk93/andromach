// The parts of the Linux arm64 user ABI the runtime implements: system call numbers
// (asm-generic), flag values and structure layouts, as the guest sees them.
#pragma once
#include <stdint.h>

// ---- system calls ------------------------------------------------------------------------
#define LINUX_SYS_getcwd 17
#define LINUX_SYS_eventfd2 19
#define LINUX_SYS_epoll_create1 20
#define LINUX_SYS_epoll_ctl 21
#define LINUX_SYS_epoll_pwait 22
#define LINUX_SYS_dup 23
#define LINUX_SYS_dup3 24
#define LINUX_SYS_fcntl 25
#define LINUX_SYS_inotify_init1 26
#define LINUX_SYS_ioctl 29
#define LINUX_SYS_flock 32
#define LINUX_SYS_mknodat 33
#define LINUX_SYS_mkdirat 34
#define LINUX_SYS_unlinkat 35
#define LINUX_SYS_symlinkat 36
#define LINUX_SYS_linkat 37
#define LINUX_SYS_renameat 38
#define LINUX_SYS_statfs 43
#define LINUX_SYS_fstatfs 44
#define LINUX_SYS_truncate 45
#define LINUX_SYS_ftruncate 46
#define LINUX_SYS_faccessat 48
#define LINUX_SYS_chdir 49
#define LINUX_SYS_fchdir 50
#define LINUX_SYS_fchmod 52
#define LINUX_SYS_fchmodat 53
#define LINUX_SYS_fchownat 54
#define LINUX_SYS_fchown 55
#define LINUX_SYS_openat 56
#define LINUX_SYS_close 57
#define LINUX_SYS_pipe2 59
#define LINUX_SYS_getdents64 61
#define LINUX_SYS_lseek 62
#define LINUX_SYS_read 63
#define LINUX_SYS_write 64
#define LINUX_SYS_readv 65
#define LINUX_SYS_writev 66
#define LINUX_SYS_pread64 67
#define LINUX_SYS_pwrite64 68
#define LINUX_SYS_sendfile 71
#define LINUX_SYS_pselect6 72
#define LINUX_SYS_ppoll 73
#define LINUX_SYS_readlinkat 78
#define LINUX_SYS_newfstatat 79
#define LINUX_SYS_fstat 80
#define LINUX_SYS_sync 81
#define LINUX_SYS_fsync 82
#define LINUX_SYS_fdatasync 83
#define LINUX_SYS_timerfd_create 85
#define LINUX_SYS_utimensat 88
#define LINUX_SYS_capget 90
#define LINUX_SYS_capset 91
#define LINUX_SYS_exit 93
#define LINUX_SYS_exit_group 94
#define LINUX_SYS_waitid 95
#define LINUX_SYS_set_tid_address 96
#define LINUX_SYS_futex 98
#define LINUX_SYS_set_robust_list 99
#define LINUX_SYS_nanosleep 101
#define LINUX_SYS_getitimer 102
#define LINUX_SYS_setitimer 103
#define LINUX_SYS_clock_gettime 113
#define LINUX_SYS_clock_getres 114
#define LINUX_SYS_clock_nanosleep 115
#define LINUX_SYS_sched_setscheduler 119
#define LINUX_SYS_sched_getscheduler 120
#define LINUX_SYS_sched_getparam 121
#define LINUX_SYS_sched_setaffinity 122
#define LINUX_SYS_sched_getaffinity 123
#define LINUX_SYS_sched_yield 124
#define LINUX_SYS_kill 129
#define LINUX_SYS_tkill 130
#define LINUX_SYS_tgkill 131
#define LINUX_SYS_sigaltstack 132
#define LINUX_SYS_rt_sigsuspend 133
#define LINUX_SYS_rt_sigaction 134
#define LINUX_SYS_rt_sigprocmask 135
#define LINUX_SYS_rt_sigpending 136
#define LINUX_SYS_rt_sigtimedwait 137
#define LINUX_SYS_rt_sigreturn 139
#define LINUX_SYS_setpriority 140
#define LINUX_SYS_getpriority 141
#define LINUX_SYS_setregid 143
#define LINUX_SYS_setgid 144
#define LINUX_SYS_setreuid 145
#define LINUX_SYS_setuid 146
#define LINUX_SYS_setresuid 147
#define LINUX_SYS_getresuid 148
#define LINUX_SYS_setresgid 149
#define LINUX_SYS_getresgid 150
#define LINUX_SYS_setfsuid 151
#define LINUX_SYS_setfsgid 152
#define LINUX_SYS_times 153
#define LINUX_SYS_setpgid 154
#define LINUX_SYS_getpgid 155
#define LINUX_SYS_getsid 156
#define LINUX_SYS_setsid 157
#define LINUX_SYS_getgroups 158
#define LINUX_SYS_setgroups 159
#define LINUX_SYS_uname 160
#define LINUX_SYS_sethostname 161
#define LINUX_SYS_getrlimit 163
#define LINUX_SYS_setrlimit 164
#define LINUX_SYS_getrusage 165
#define LINUX_SYS_umask 166
#define LINUX_SYS_prctl 167
#define LINUX_SYS_getcpu 168
#define LINUX_SYS_gettimeofday 169
#define LINUX_SYS_getpid 172
#define LINUX_SYS_getppid 173
#define LINUX_SYS_getuid 174
#define LINUX_SYS_geteuid 175
#define LINUX_SYS_getgid 176
#define LINUX_SYS_getegid 177
#define LINUX_SYS_gettid 178
#define LINUX_SYS_sysinfo 179
#define LINUX_SYS_socket 198
#define LINUX_SYS_socketpair 199
#define LINUX_SYS_bind 200
#define LINUX_SYS_listen 201
#define LINUX_SYS_accept 202
#define LINUX_SYS_connect 203
#define LINUX_SYS_getsockname 204
#define LINUX_SYS_getpeername 205
#define LINUX_SYS_sendto 206
#define LINUX_SYS_recvfrom 207
#define LINUX_SYS_setsockopt 208
#define LINUX_SYS_getsockopt 209
#define LINUX_SYS_shutdown 210
#define LINUX_SYS_sendmsg 211
#define LINUX_SYS_recvmsg 212
#define LINUX_SYS_brk 214
#define LINUX_SYS_munmap 215
#define LINUX_SYS_mremap 216
#define LINUX_SYS_clone 220
#define LINUX_SYS_execve 221
#define LINUX_SYS_mmap 222
#define LINUX_SYS_fadvise64 223
#define LINUX_SYS_mprotect 226
#define LINUX_SYS_msync 227
#define LINUX_SYS_mlock 228
#define LINUX_SYS_munlock 229
#define LINUX_SYS_mincore 232
#define LINUX_SYS_madvise 233
#define LINUX_SYS_accept4 242
#define LINUX_SYS_wait4 260
#define LINUX_SYS_prlimit64 261
#define LINUX_SYS_renameat2 276
#define LINUX_SYS_syncfs 267
#define LINUX_SYS_getrandom 278
#define LINUX_SYS_memfd_create 279
#define LINUX_SYS_membarrier 283
#define LINUX_SYS_mlock2 284
#define LINUX_SYS_statx 291
#define LINUX_SYS_rseq 293
#define LINUX_SYS_pidfd_open 434
#define LINUX_SYS_clone3 435
#define LINUX_SYS_close_range 436
#define LINUX_SYS_faccessat2 439

// ---- errno -------------------------------------------------------------------------------
#define LINUX_EPERM 1
#define LINUX_ENOENT 2
#define LINUX_ESRCH 3
#define LINUX_EINTR 4
#define LINUX_EIO 5
#define LINUX_EBADF 9
#define LINUX_ECHILD 10
#define LINUX_EAGAIN 11
#define LINUX_ENOMEM 12
#define LINUX_EACCES 13
#define LINUX_EFAULT 14
#define LINUX_EBUSY 16
#define LINUX_EEXIST 17
#define LINUX_ENOTDIR 20
#define LINUX_EISDIR 21
#define LINUX_EINVAL 22
#define LINUX_EMFILE 24
#define LINUX_ENOTTY 25
#define LINUX_ERANGE 34
#define LINUX_ENAMETOOLONG 36
#define LINUX_ENOSYS 38
#define LINUX_ELOOP 40
#define LINUX_ETIMEDOUT 110

// ---- open / at ---------------------------------------------------------------------------
#define LINUX_O_RDONLY 0
#define LINUX_O_WRONLY 1
#define LINUX_O_RDWR 2
#define LINUX_O_CREAT 0x40
#define LINUX_O_EXCL 0x80
#define LINUX_O_NOCTTY 0x100
#define LINUX_O_TRUNC 0x200
#define LINUX_O_APPEND 0x400
#define LINUX_O_NONBLOCK 0x800
#define LINUX_O_DSYNC 0x1000
#define LINUX_O_DIRECTORY 0x4000
#define LINUX_O_NOFOLLOW 0x8000
#define LINUX_O_CLOEXEC 0x80000
#define LINUX_O_PATH 0x200000

#define LINUX_AT_FDCWD -100
#define LINUX_AT_SYMLINK_NOFOLLOW 0x100
#define LINUX_AT_REMOVEDIR 0x200
#define LINUX_AT_EMPTY_PATH 0x1000

#define LINUX_F_DUPFD 0
#define LINUX_F_GETFD 1
#define LINUX_F_SETFD 2
#define LINUX_F_GETFL 3
#define LINUX_F_SETFL 4
#define LINUX_F_GETLK 5
#define LINUX_F_SETLK 6
#define LINUX_F_SETLKW 7
#define LINUX_F_OFD_GETLK 36
#define LINUX_F_OFD_SETLK 37
#define LINUX_F_OFD_SETLKW 38
#define LINUX_F_DUPFD_CLOEXEC 1030
#define LINUX_F_ADD_SEALS 1033
#define LINUX_F_GET_SEALS 1034
#define LINUX_F_SETPIPE_SZ 1031
#define LINUX_F_GETPIPE_SZ 1032

// ---- ioctl -------------------------------------------------------------------------------
#define LINUX_TCGETS 0x5401
#define LINUX_TCSETS 0x5402
#define LINUX_TCSETSW 0x5403
#define LINUX_TCSETSF 0x5404
#define LINUX_TIOCGPGRP 0x540F
#define LINUX_TIOCSPGRP 0x5410
#define LINUX_TIOCGWINSZ 0x5413
#define LINUX_TIOCSWINSZ 0x5414
#define LINUX_FIONREAD 0x541B
#define LINUX_FIONBIO 0x5421

// ---- memory ------------------------------------------------------------------------------
#define LINUX_PROT_READ 1
#define LINUX_PROT_WRITE 2
#define LINUX_PROT_EXEC 4
#define LINUX_MAP_SHARED 0x01
#define LINUX_MAP_PRIVATE 0x02
#define LINUX_MAP_FIXED 0x10
#define LINUX_MAP_ANONYMOUS 0x20
#define LINUX_MAP_NORESERVE 0x4000
#define LINUX_MAP_FIXED_NOREPLACE 0x100000
#define LINUX_MADV_DONTNEED 4
#define LINUX_MREMAP_MAYMOVE 1
#define LINUX_MREMAP_FIXED 2

// ---- threads -----------------------------------------------------------------------------
#define LINUX_CLONE_VM 0x100
#define LINUX_CLONE_FS 0x200
#define LINUX_CLONE_FILES 0x400
#define LINUX_CLONE_SIGHAND 0x800
#define LINUX_CLONE_VFORK 0x4000
#define LINUX_CLONE_THREAD 0x10000
#define LINUX_CLONE_SETTLS 0x80000
#define LINUX_CLONE_PARENT_SETTID 0x100000
#define LINUX_CLONE_CHILD_CLEARTID 0x200000
#define LINUX_CLONE_CHILD_SETTID 0x1000000

#define LINUX_FUTEX_WAIT 0
#define LINUX_FUTEX_WAKE 1
#define LINUX_FUTEX_REQUEUE 3
#define LINUX_FUTEX_CMP_REQUEUE 4
#define LINUX_FUTEX_WAKE_OP 5
#define LINUX_FUTEX_LOCK_PI 6
#define LINUX_FUTEX_UNLOCK_PI 7
#define LINUX_FUTEX_WAIT_BITSET 9
#define LINUX_FUTEX_WAKE_BITSET 10
#define LINUX_FUTEX_PRIVATE_FLAG 128
#define LINUX_FUTEX_CLOCK_REALTIME 256

// ---- structures --------------------------------------------------------------------------
struct linux_timespec { int64_t tv_sec, tv_nsec; };

struct linux_stat {
    uint64_t st_dev, st_ino;
    uint32_t st_mode, st_nlink, st_uid, st_gid;
    uint64_t st_rdev, __pad1;
    int64_t st_size;
    int32_t st_blksize, __pad2;
    int64_t st_blocks;
    int64_t st_atime_; uint64_t st_atime_nsec;
    int64_t st_mtime_; uint64_t st_mtime_nsec;
    int64_t st_ctime_; uint64_t st_ctime_nsec;
    uint32_t __reserved[2];
};
_Static_assert(sizeof(struct linux_stat) == 128, "linux stat");

struct linux_statx_timestamp { int64_t tv_sec; uint32_t tv_nsec; int32_t __reserved; };
struct linux_statx {
    uint32_t stx_mask, stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink, stx_uid, stx_gid;
    uint16_t stx_mode, __spare0;
    uint64_t stx_ino, stx_size, stx_blocks, stx_attributes_mask;
    struct linux_statx_timestamp stx_atime, stx_btime, stx_ctime, stx_mtime;
    uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
    uint64_t __spare2[14];
};
_Static_assert(sizeof(struct linux_statx) == 256, "linux statx");

struct linux_statfs {
    int64_t f_type, f_bsize;
    uint64_t f_blocks, f_bfree, f_bavail, f_files, f_ffree;
    int32_t f_fsid[2];
    int64_t f_namelen, f_frsize, f_flags, f_spare[4];
};

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
};

struct linux_termios {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t c_line, c_cc[19];
};

struct linux_flock { int16_t l_type, l_whence; int64_t l_start, l_len; int32_t l_pid; };

struct linux_utsname { char sysname[65], nodename[65], release[65], version[65], machine[65], domainname[65]; };

struct linux_rlimit { uint64_t cur, max; };

struct linux_sysinfo {
    int64_t uptime;
    uint64_t loads[3], totalram, freeram, sharedram, bufferram, totalswap, freeswap;
    uint16_t procs, pad;
    uint64_t totalhigh, freehigh;
    uint32_t mem_unit;
    char _f[4];
};

// ---- binder (include/uapi/linux/android/binder.h, 64-bit protocol 8) -----------------------
#define LINUX_IOC(dir, type, nr, size) (((uint32_t)(dir) << 30) | ((uint32_t)(size) << 16) | ((type) << 8) | (nr))
#define LINUX_IO(t, n) LINUX_IOC(0, t, n, 0)
#define LINUX_IOW(t, n, sz) LINUX_IOC(1, t, n, sz)
#define LINUX_IOR(t, n, sz) LINUX_IOC(2, t, n, sz)
#define LINUX_IOWR(t, n, sz) LINUX_IOC(3, t, n, sz)
#define LINUX_IOC_SIZE(c) (((c) >> 16) & 0x3FFF)

#define BINDER_PACK(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (d))
#define BINDER_TYPE_BINDER BINDER_PACK('s', 'b', '*', 0x85)
#define BINDER_TYPE_WEAK_BINDER BINDER_PACK('w', 'b', '*', 0x85)
#define BINDER_TYPE_HANDLE BINDER_PACK('s', 'h', '*', 0x85)
#define BINDER_TYPE_WEAK_HANDLE BINDER_PACK('w', 'h', '*', 0x85)
#define BINDER_TYPE_FD BINDER_PACK('f', 'd', '*', 0x85)
#define BINDER_TYPE_FDA BINDER_PACK('f', 'd', 'a', 0x85)
#define BINDER_TYPE_PTR BINDER_PACK('p', 't', '*', 0x85)

#define FLAT_BINDER_FLAG_ACCEPTS_FDS 0x100
#define FLAT_BINDER_FLAG_TXN_SECURITY_CTX 0x1000
#define BINDER_BUFFER_FLAG_HAS_PARENT 0x01

#define TF_ONE_WAY 0x01
#define TF_ROOT_OBJECT 0x04
#define TF_STATUS_CODE 0x08
#define TF_ACCEPT_FDS 0x10
#define TF_CLEAR_BUF 0x20
#define TF_UPDATE_TXN 0x40

#define BINDER_CURRENT_PROTOCOL_VERSION 8

struct flat_binder_object {
    uint32_t type, flags;
    union { uint64_t binder; uint32_t handle; };
    uint64_t cookie;
};
struct binder_fd_object {
    uint32_t type, pad_flags;
    union { uint64_t pad_binder; uint32_t fd; };
    uint64_t cookie;
};
struct binder_buffer_object {
    uint32_t type, flags;
    uint64_t buffer, length, parent, parent_offset;
};
struct binder_fd_array_object {
    uint32_t type, pad;
    uint64_t num_fds, parent, parent_offset;
};
struct binder_write_read {
    uint64_t write_size, write_consumed, write_buffer;
    uint64_t read_size, read_consumed, read_buffer;
};
struct binder_version { int32_t protocol_version; };
struct binder_transaction_data {
    union { uint32_t handle; uint64_t ptr; } target;
    uint64_t cookie;
    uint32_t code, flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    uint64_t data_size, offsets_size;
    union { struct { uint64_t buffer, offsets; } ptr; uint8_t buf[8]; } data;
};
struct binder_transaction_data_secctx { struct binder_transaction_data transaction_data; uint64_t secctx; };
struct binder_transaction_data_sg { struct binder_transaction_data transaction_data; uint64_t buffers_size; };
struct binder_ptr_cookie { uint64_t ptr, cookie; };
struct __attribute__((packed)) binder_handle_cookie { uint32_t handle; uint64_t cookie; };
struct binder_node_debug_info { uint64_t ptr, cookie; uint32_t has_strong_ref, has_weak_ref; };
struct binder_node_info_for_ref { uint32_t handle, strong_count, weak_count, reserved1, reserved2, reserved3; };
struct binder_freeze_info { uint32_t pid, enable, timeout_ms; };
struct binder_frozen_status_info { uint32_t pid, sync_recv, async_recv; };
struct binder_extended_error { uint32_t id, command; int32_t param; };
_Static_assert(sizeof(struct binder_transaction_data) == 64, "binder_transaction_data");
_Static_assert(sizeof(struct binder_handle_cookie) == 12, "binder_handle_cookie");
_Static_assert(sizeof(struct binder_buffer_object) == 40, "binder_buffer_object");
_Static_assert(sizeof(struct binder_fd_array_object) == 32, "binder_fd_array_object");

#define BINDER_WRITE_READ LINUX_IOWR('b', 1, sizeof(struct binder_write_read))
#define BINDER_SET_IDLE_TIMEOUT LINUX_IOW('b', 3, 8)
#define BINDER_SET_MAX_THREADS LINUX_IOW('b', 5, 4)
#define BINDER_SET_IDLE_PRIORITY LINUX_IOW('b', 6, 4)
#define BINDER_SET_CONTEXT_MGR LINUX_IOW('b', 7, 4)
#define BINDER_THREAD_EXIT LINUX_IOW('b', 8, 4)
#define BINDER_VERSION LINUX_IOWR('b', 9, sizeof(struct binder_version))
#define BINDER_GET_NODE_DEBUG_INFO LINUX_IOWR('b', 11, sizeof(struct binder_node_debug_info))
#define BINDER_GET_NODE_INFO_FOR_REF LINUX_IOWR('b', 12, sizeof(struct binder_node_info_for_ref))
#define BINDER_SET_CONTEXT_MGR_EXT LINUX_IOW('b', 13, sizeof(struct flat_binder_object))
#define BINDER_FREEZE LINUX_IOW('b', 14, sizeof(struct binder_freeze_info))
#define BINDER_GET_FROZEN_INFO LINUX_IOWR('b', 15, sizeof(struct binder_frozen_status_info))
#define BINDER_ENABLE_ONEWAY_SPAM_DETECTION LINUX_IOW('b', 16, 4)
#define BINDER_GET_EXTENDED_ERROR LINUX_IOWR('b', 17, sizeof(struct binder_extended_error))

#define BC_TRANSACTION LINUX_IOW('c', 0, sizeof(struct binder_transaction_data))
#define BC_REPLY LINUX_IOW('c', 1, sizeof(struct binder_transaction_data))
#define BC_ACQUIRE_RESULT LINUX_IOW('c', 2, 4)
#define BC_FREE_BUFFER LINUX_IOW('c', 3, 8)
#define BC_INCREFS LINUX_IOW('c', 4, 4)
#define BC_ACQUIRE LINUX_IOW('c', 5, 4)
#define BC_RELEASE LINUX_IOW('c', 6, 4)
#define BC_DECREFS LINUX_IOW('c', 7, 4)
#define BC_INCREFS_DONE LINUX_IOW('c', 8, sizeof(struct binder_ptr_cookie))
#define BC_ACQUIRE_DONE LINUX_IOW('c', 9, sizeof(struct binder_ptr_cookie))
#define BC_ATTEMPT_ACQUIRE LINUX_IOW('c', 10, 8)
#define BC_REGISTER_LOOPER LINUX_IO('c', 11)
#define BC_ENTER_LOOPER LINUX_IO('c', 12)
#define BC_EXIT_LOOPER LINUX_IO('c', 13)
#define BC_REQUEST_DEATH_NOTIFICATION LINUX_IOW('c', 14, sizeof(struct binder_handle_cookie))
#define BC_CLEAR_DEATH_NOTIFICATION LINUX_IOW('c', 15, sizeof(struct binder_handle_cookie))
#define BC_DEAD_BINDER_DONE LINUX_IOW('c', 16, 8)
#define BC_TRANSACTION_SG LINUX_IOW('c', 17, sizeof(struct binder_transaction_data_sg))
#define BC_REPLY_SG LINUX_IOW('c', 18, sizeof(struct binder_transaction_data_sg))
#define BC_REQUEST_FREEZE_NOTIFICATION LINUX_IOW('c', 19, sizeof(struct binder_handle_cookie))
#define BC_CLEAR_FREEZE_NOTIFICATION LINUX_IOW('c', 20, sizeof(struct binder_handle_cookie))
#define BC_FREEZE_NOTIFICATION_DONE LINUX_IOW('c', 21, 8)

#define BR_ERROR LINUX_IOR('r', 0, 4)
#define BR_OK LINUX_IO('r', 1)
#define BR_TRANSACTION_SEC_CTX LINUX_IOR('r', 2, sizeof(struct binder_transaction_data_secctx))
#define BR_TRANSACTION LINUX_IOR('r', 2, sizeof(struct binder_transaction_data))
#define BR_REPLY LINUX_IOR('r', 3, sizeof(struct binder_transaction_data))
#define BR_DEAD_REPLY LINUX_IO('r', 5)
#define BR_TRANSACTION_COMPLETE LINUX_IO('r', 6)
#define BR_INCREFS LINUX_IOR('r', 7, sizeof(struct binder_ptr_cookie))
#define BR_ACQUIRE LINUX_IOR('r', 8, sizeof(struct binder_ptr_cookie))
#define BR_RELEASE LINUX_IOR('r', 9, sizeof(struct binder_ptr_cookie))
#define BR_DECREFS LINUX_IOR('r', 10, sizeof(struct binder_ptr_cookie))
#define BR_NOOP LINUX_IO('r', 12)
#define BR_SPAWN_LOOPER LINUX_IO('r', 13)
#define BR_DEAD_BINDER LINUX_IOR('r', 15, 8)
#define BR_CLEAR_DEATH_NOTIFICATION_DONE LINUX_IOR('r', 16, 8)
#define BR_FAILED_REPLY LINUX_IO('r', 17)
#define BR_FROZEN_REPLY LINUX_IO('r', 18)
#define BR_ONEWAY_SPAM_SUSPECT LINUX_IO('r', 19)
