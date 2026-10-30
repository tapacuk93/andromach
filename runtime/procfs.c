// /proc and /sys: files generated when opened, with the contents Android's userland reads
// (process status, memory and CPU summaries, the boot id, and selinuxfs). Each open gets a
// fresh unlinked host file, so read, pread, fstat and mmap all work on it; writes are accepted
// and dropped, which is what writable knobs such as oom_score_adj need here.
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
#include <sys/sysctl.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct { char *b; size_t n, cap; } buf;

static void put(buf *o, const void *s, size_t n) {
    if (o->n + n > o->cap) o->b = realloc(o->b, o->cap = (o->n + n) * 2 + 256);
    memcpy(o->b + o->n, s, n);
    o->n += n;
}

static void putf(buf *o, const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    put(o, tmp, n < (int)sizeof tmp ? (size_t)n : sizeof tmp - 1);
}

static uint64_t mem_total(void) {
    uint64_t m = 0;
    size_t sz = sizeof m;
    sysctlbyname("hw.memsize", &m, &sz, NULL, 0);
    return m;
}

static int ncpu(void) {
    int n = 0;
    size_t sz = sizeof n;
    sysctlbyname("hw.ncpu", &n, &sz, NULL, 0);
    return n;
}

static const char *comm_of(am_proc *p) {
    const char *s = strrchr(p->exe, '/');
    return s ? s + 1 : p->exe;
}

static void proc_maps(buf *o, am_proc *p) {
    pthread_mutex_lock(&p->vm_lock);
    for (int i = 0; i < p->nvma; i++) {
        am_vma *v = &p->vmas[i];
        // One line per kernel map entry, for the real protections.
        mach_vm_address_t a = v->start;
        while (a < v->end) {
            mach_vm_address_t r = a;
            mach_vm_size_t sz;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj;
            if (mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) ||
                r >= v->end)
                break;
            uint64_t s = r > a ? r : a, e = r + sz < v->end ? r + sz : v->end;
            putf(o, "%llx-%llx %c%c%c%c 00000000 00:00 0\n", (unsigned long long)s, (unsigned long long)e,
                 info.protection & 1 ? 'r' : '-', info.protection & 2 ? 'w' : '-', info.protection & 4 ? 'x' : '-',
                 v->shared ? 's' : 'p');
            a = e;
        }
    }
    pthread_mutex_unlock(&p->vm_lock);
}

// Contents for a /proc/<pid>/... file of process p; false if there is no such file.
static bool proc_pid_file(buf *o, am_proc *p, const char *rest) {
    if (!strcmp(rest, "cmdline")) { put(o, p->cmdline, p->cmdline_len); return true; }
    if (!strcmp(rest, "comm")) { putf(o, "%.15s\n", comm_of(p)); return true; }
    if (!strcmp(rest, "stat")) {
        putf(o, "%d (%.15s) R %d %d %d 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 %d 0 0 0 0 "
                "18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
             p->pid, comm_of(p), p->ppid, p->pgid, p->sid, p->nthreads);
        return true;
    }
    if (!strcmp(rest, "status")) {
        putf(o, "Name:\t%.15s\nUmask:\t%04o\nState:\tR (running)\nTgid:\t%d\nNgid:\t0\nPid:\t%d\nPPid:\t%d\n"
                "TracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t%d\nGroups:\t\nThreads:\t%d\n"
                "SigQ:\t0/0\nSigPnd:\t0000000000000000\nShdPnd:\t%016llx\nCapEff:\t000001ffffffffff\n"
                "VmRSS:\t   10000 kB\n",
             comm_of(p), p->umask, p->pid, p->pid, p->ppid, AM_MAX_FDS, p->nthreads, (unsigned long long)p->sigpending);
        return true;
    }
    if (!strcmp(rest, "maps") || !strcmp(rest, "smaps")) { proc_maps(o, p); return true; }
    if (!strncmp(rest, "attr/", 5)) {
        // SELinux contexts: everything runs in one permissive domain.
        const char *a = strrchr(rest, '/') + 1;
        if (!strcmp(a, "current") || !strcmp(a, "prev")) { put(o, "u:r:su:s0", 10); return true; }
        return true;  // exec, fscreate, keycreate, sockcreate: empty
    }
    if (!strcmp(rest, "oom_score_adj") || !strcmp(rest, "oom_adj") || !strcmp(rest, "oom_score")) {
        putf(o, "0\n");
        return true;
    }
    if (!strcmp(rest, "mounts") || !strcmp(rest, "mountinfo")) {
        putf(o, "/dev/root / ext4 ro 0 0\ntmpfs /dev tmpfs rw 0 0\nproc /proc proc rw 0 0\n"
                "sysfs /sys sysfs rw 0 0\nselinuxfs /sys/fs/selinux selinuxfs rw 0 0\n"
                "/dev/block/data /data ext4 rw 0 0\n");
        return true;
    }
    if (!strcmp(rest, "environ") || !strcmp(rest, "limits") || !strcmp(rest, "cgroup") || !strcmp(rest, "auxv"))
        return true;
    if (!strcmp(rest, "schedstat")) { putf(o, "0 0 0\n"); return true; }
    if (!strcmp(rest, "timerslack_ns")) { putf(o, "50000\n"); return true; }
    return false;
}

static bool proc_file(buf *o, const char *path) {
    am_proc *self = am_self->proc;
    int pid, n;
    if (sscanf(path, "/proc/%d/%n", &pid, &n) == 1 && n > 0) {
        am_proc *p = pid == self->pid ? self : am_proc_get(pid);
        if (!p) return false;
        const char *rest = path + n;
        int tid, m;
        if (sscanf(rest, "task/%d/%n", &tid, &m) == 1 && m > 0) rest += m;  // a thread: same answers
        return proc_pid_file(o, p, rest);
    }
    if (!strcmp(path, "/proc/cpuinfo")) {
        for (int i = 0; i < ncpu(); i++)
            putf(o, "processor\t: %d\nBogoMIPS\t: 48.00\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics "
                    "fphp asimdhp asimdrdm jscvt fcma lrcpc dcpop sha3 asimddp sha512 asimdfhm dit uscat ilrcpc flagm ssbs sb\n"
                    "CPU implementer\t: 0x61\nCPU architecture: 8\nCPU variant\t: 0x1\nCPU part\t: 0x022\nCPU revision\t: 1\n\n", i);
        return true;
    }
    if (!strcmp(path, "/proc/meminfo")) {
        uint64_t kb = mem_total() / 1024;
        putf(o, "MemTotal:       %llu kB\nMemFree:        %llu kB\nMemAvailable:   %llu kB\nBuffers:        0 kB\n"
                "Cached:         0 kB\nSwapTotal:      0 kB\nSwapFree:       0 kB\n",
             (unsigned long long)kb, (unsigned long long)kb / 2, (unsigned long long)kb / 2);
        return true;
    }
    if (!strcmp(path, "/proc/stat")) {
        putf(o, "cpu  0 0 0 0 0 0 0 0 0 0\n");
        for (int i = 0; i < ncpu(); i++) putf(o, "cpu%d 0 0 0 0 0 0 0 0 0 0\n", i);
        putf(o, "btime %ld\nprocesses 1\nprocs_running 1\nprocs_blocked 0\n", (long)time(NULL));
        return true;
    }
    if (!strcmp(path, "/proc/uptime")) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        putf(o, "%ld.%02ld 0.00\n", (long)ts.tv_sec, ts.tv_nsec / 10000000);
        return true;
    }
    if (!strcmp(path, "/proc/loadavg")) { putf(o, "0.00 0.00 0.00 1/1 %d\n", self->pid); return true; }
    if (!strcmp(path, "/proc/version")) { putf(o, "Linux version 6.6.0-andromach (andromach) #1 SMP PREEMPT\n"); return true; }
    if (!strcmp(path, "/proc/cmdline")) {
        putf(o, "androidboot.hardware=ranchu androidboot.selinux=permissive androidboot.serialno=ANDROMACH\n");
        return true;
    }
    if (!strcmp(path, "/proc/filesystems")) {
        putf(o, "nodev\tsysfs\nnodev\ttmpfs\nnodev\tproc\nnodev\tselinuxfs\n\text4\n\terofs\n");
        return true;
    }
    if (!strcmp(path, "/proc/mounts")) return proc_pid_file(o, self, "mounts");
    if (!strcmp(path, "/proc/sys/kernel/random/boot_id") || !strcmp(path, "/proc/sys/kernel/random/uuid")) {
        // boot_id stays the same for the life of the runtime; uuid is new on every read.
        static uint8_t boot[16];
        uint8_t fresh[16], *r = boot;
        if (strstr(path, "uuid")) { arc4random_buf(fresh, sizeof fresh); r = fresh; }
        else if (!boot[6]) { arc4random_buf(boot, sizeof boot); boot[6] = (boot[6] & 0x0F) | 0x40; }
        putf(o, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", r[0], r[1], r[2], r[3], r[4],
             r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
        return true;
    }
    if (!strncmp(path, "/proc/sys/", 10)) {
        if (strstr(path, "pid_max")) putf(o, "32768\n");
        else if (strstr(path, "osrelease")) putf(o, "6.6.0-andromach\n");
        else if (strstr(path, "hostname")) putf(o, "localhost\n");
        else putf(o, "0\n");
        return true;
    }
    return false;
}

// selinuxfs, as libselinux reads it: permissive, with a status page it can map.
static bool sys_file(buf *o, const char *path) {
    if (!strcmp(path, "/sys/fs/selinux/status")) {
        uint32_t st[5] = {1 /* version */, 0 /* sequence */, 0 /* enforcing */, 1 /* policyload */, 0};
        put(o, st, sizeof st);
        char pad[AM_PAGE - sizeof st];
        memset(pad, 0, sizeof pad);
        put(o, pad, sizeof pad);  // a full page, so it can be mapped
        return true;
    }
    if (!strcmp(path, "/sys/fs/selinux/enforce") || !strcmp(path, "/sys/fs/selinux/checkreqprot") ||
        !strcmp(path, "/sys/fs/selinux/deny_unknown") || !strcmp(path, "/sys/fs/selinux/reject_unknown")) {
        putf(o, "0");
        return true;
    }
    if (!strcmp(path, "/sys/fs/selinux/mls")) { putf(o, "1"); return true; }
    if (!strcmp(path, "/sys/fs/selinux/policyvers")) { putf(o, "33"); return true; }

    if (!strncmp(path, "/sys/devices/system/cpu/", 24)) {
        if (strstr(path, "possible") || strstr(path, "present") || strstr(path, "online")) putf(o, "0-%d\n", ncpu() - 1);
        else putf(o, "0\n");
        return true;
    }
    return false;
}

typedef struct { char path[1024]; } tmpdir;

static void tmpdir_release(am_file *f) {
    tmpdir *t = f->priv;
    char cmd[1200];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", t->path);
    if (system(cmd)) {}
    free(t);
}

static const am_file_ops tmpdir_ops = {.name = "procfs-dir", .release = tmpdir_release};

typedef struct { const char *dir; } list_ctx;

static void add_pid(am_proc *p, void *arg) {
    char e[1200];
    snprintf(e, sizeof e, "%s/%d", ((list_ctx *)arg)->dir, p->pid);
    mkdir(e, 0555);
}

// Fills dir with the entries of the /proc directory path; false if path is not one.
static bool list_dir(const char *path, const char *dir) {
    char e[1200];
    if (!strcmp(path, "/proc")) {
        list_ctx c = {dir};
        am_proc_for_each(add_pid, &c);
        const char *files[] = {"self", "thread-self", "cpuinfo", "meminfo", "stat", "uptime", "version", "cmdline",
                               "filesystems", "mounts", "loadavg", "sys", NULL};
        for (const char **f = files; *f; f++) {
            snprintf(e, sizeof e, "%s/%s", dir, *f);
            if (!strcmp(*f, "sys")) mkdir(e, 0555);
            else if (!strncmp(*f, "self", 4) || !strncmp(*f, "thread", 6)) { if (symlink("/proc/1", e)) {} }
            else close(open(e, O_CREAT | O_WRONLY, 0444));
        }
        return true;
    }
    if (!strcmp(path, "/sys") || !strcmp(path, "/sys/fs") || !strcmp(path, "/sys/fs/selinux") ||
        !strcmp(path, "/proc/sys")) return true;
    int pid, n = 0;
    if (sscanf(path, "/proc/%d%n", &pid, &n) != 1) return false;
    am_proc *p = pid == am_self->proc->pid ? am_self->proc : am_proc_get(pid);
    if (!p) return false;
    const char *rest = path + n;
    if (!*rest) {
        const char *files[] = {"cmdline", "comm", "stat", "status", "maps", "smaps", "mounts", "oom_score_adj",
                               "environ", "cgroup", NULL};
        for (const char **f = files; *f; f++) {
            snprintf(e, sizeof e, "%s/%s", dir, *f);
            close(open(e, O_CREAT | O_WRONLY, 0444));
        }
        const char *dirs[] = {"task", "fd", "attr", NULL};
        for (const char **d = dirs; *d; d++) { snprintf(e, sizeof e, "%s/%s", dir, *d); mkdir(e, 0555); }
        return true;
    }
    if (!strcmp(rest, "/task")) {
        pthread_mutex_lock(&p->lock);
        for (am_thread *t = p->threads; t; t = t->next) {
            snprintf(e, sizeof e, "%s/%d", dir, t->tid);
            mkdir(e, 0555);
        }
        pthread_mutex_unlock(&p->lock);
        return true;
    }
    if (!strcmp(rest, "/fd") || !strcmp(rest, "/fdinfo")) {
        pthread_mutex_lock(&p->lock);
        for (int i = 0; i < AM_MAX_FDS; i++)
            if (p->fds[i]) {
                snprintf(e, sizeof e, "%s/%d", dir, i);
                if (symlink(p->fds[i]->gpath ? p->fds[i]->gpath : "anon_inode:[unknown]", e)) {}
            }
        pthread_mutex_unlock(&p->lock);
        return true;
    }
    int tid, m = 0;
    if (sscanf(rest, "/task/%d%n", &tid, &m) == 1 && !rest[m]) {
        // A thread's directory holds what its process's does.
        char pp[64];
        snprintf(pp, sizeof pp, "/proc/%d", p->pid);
        return list_dir(pp, dir);
    }
    if (!strcmp(rest, "/attr")) return true;
    return false;
}

static bool open_dir(const char *canon, int lflags, am_file **out, long *err) {
    tmpdir *t = malloc(sizeof *t);
    snprintf(t->path, sizeof t->path, "%s/tmp/.procdir-XXXXXX", am_datadir);
    if (!mkdtemp(t->path)) { free(t); *err = am_errno(errno); return true; }
    if (!list_dir(canon, t->path)) {
        rmdir(t->path);
        free(t);
        return false;
    }
    int fd = open(t->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { *err = am_errno(errno); free(t); return true; }
    *out = am_file_new(fd, lflags, canon, &tmpdir_ops, t);
    *err = 0;
    return true;
}

// selinuxfs transaction files: libselinux writes a question and reads the answer from the same
// open file. With one domain for everything, every answer is "allowed" and "u:r:su:s0".
typedef struct { const char *answer; size_t len; bool asked; size_t pos; } transaction;

static long tx_write(am_file *f, const void *b, size_t n) {
    transaction *t = f->priv;
    t->asked = true;
    t->pos = 0;
    return n;
}

static long tx_read(am_file *f, void *b, size_t n) {
    transaction *t = f->priv;
    if (!t->asked || t->pos >= t->len) return 0;
    if (n > t->len - t->pos) n = t->len - t->pos;
    memcpy(b, t->answer + t->pos, n);
    t->pos += n;
    return n;
}

static void tx_release(am_file *f) { free(f->priv); }

static const am_file_ops tx_ops = {.name = "selinuxfs", .read = tx_read, .write = tx_write, .release = tx_release};

static bool open_transaction(const char *canon, int lflags, am_file **out) {
    static const char context[] = "u:r:su:s0";
    static const char access_ok[] = "ffffffff ffffffff 0 ffffffff 1 0";
    const char *names[] = {"/sys/fs/selinux/create", "/sys/fs/selinux/member", "/sys/fs/selinux/relabel",
                           "/sys/fs/selinux/user", "/sys/fs/selinux/context", "/sys/fs/selinux/access", NULL};
    for (int i = 0; names[i]; i++) {
        if (strcmp(canon, names[i])) continue;
        transaction *t = calloc(1, sizeof *t);
        bool access = !strcmp(canon, "/sys/fs/selinux/access");
        t->answer = access ? access_ok : context;
        t->len = access ? sizeof access_ok - 1 : sizeof context;
        *out = am_file_new(-1, lflags, canon, &tx_ops, t);
        return true;
    }
    return false;
}

static bool under_proc(const char *p) { return !strncmp(p, "/proc", 5) && (!p[5] || p[5] == '/'); }

long am_procfs_open(const char *canon, int lflags, am_file **out) {
    char host[4096];
    long err;
    if (open_transaction(canon, lflags, out)) return 0;
    if (open_dir(canon, lflags, out, &err)) return err;
    buf o = {0};
    bool found = under_proc(canon) ? proc_file(&o, canon) : sys_file(&o, canon);
    if (!found) { free(o.b); return AM_ERR(LINUX_ENOENT); }
    snprintf(host, sizeof host, "%s/tmp/.procfs-XXXXXX", am_datadir);
    int fd = mkstemp(host);
    if (fd < 0) { free(o.b); return am_errno(errno); }
    unlink(host);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (o.n && write(fd, o.b, o.n) != (ssize_t)o.n) { close(fd); free(o.b); return AM_ERR(LINUX_EIO); }
    free(o.b);
    lseek(fd, 0, SEEK_SET);
    *out = am_file_new(fd, lflags, canon, NULL, NULL);
    return 0;
}
