// Files: the guest's view of paths (its root, writable mounts, /dev, /proc), the fd table, and
// the file system calls. Precompiled images are shown to the guest as the ELF file they hold.
#include "am.h"
#include "linux.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <termios.h>
#include <unistd.h>

// ---- mounts ------------------------------------------------------------------------------
// Guest directories backed by the writable data directory rather than the read-only root.
static const char *writable[] = {"/data", "/tmp", "/cache", "/mnt", "/storage", "/data_mirror",
                                 "/metadata", "/linkerconfig", "/debug_ramdisk", NULL};
// Host device nodes the guest may open.
static const char *devices[] = {"null", "zero", "random", "urandom", "tty", "ptmx", NULL};

// /dev/kmsg: the kernel log, where init writes before logd exists. It goes to the host's stderr.
static long kmsg_write(am_file *f, const void *b, size_t n) {
    const char *s = b;
    size_t skip = 0;
    if (n > 3 && s[0] == '<' && s[2] == '>') skip = 3;  // the "<6>" priority prefix
    if (write(2, s + skip, n - skip) < 0) return am_errno(errno);
    return n;
}
static long kmsg_read(am_file *f, void *b, size_t n) { return AM_ERR(LINUX_EAGAIN); }
static const am_file_ops kmsg_ops = {.name = "kmsg", .read = kmsg_read, .write = kmsg_write};
static long kmsg_open(const char *name, int lflags, am_file **out) {
    *out = am_file_new(dup(2), lflags, "/dev/kmsg", &kmsg_ops, NULL);
    return 0;
}

void am_fs_register_devices(void) {
    am_dev_register("kmsg", kmsg_open);
    am_dev_register("kmsg_debug", kmsg_open);
}

static struct { const char *name; am_dev_open_fn open; } devs[32];
static int ndevs;

void am_dev_register(const char *name, am_dev_open_fn open) {
    devs[ndevs].name = name;
    devs[ndevs].open = open;
    ndevs++;
}

static am_dev_open_fn dev_lookup(const char *canon) {
    if (strncmp(canon, "/dev/", 5)) return NULL;
    for (int i = 0; i < ndevs; i++)
        if (!strcmp(canon + 5, devs[i].name)) return devs[i].open;
    return NULL;
}

static bool under(const char *path, const char *prefix) {
    size_t n = strlen(prefix);
    return strncmp(path, prefix, n) == 0 && (path[n] == 0 || path[n] == '/');
}

// Host path for a canonical guest path. Returns 0, or a negative Linux errno.
static int host_path(const char *canon, char *out, size_t n) {
    for (const char **w = writable; *w; w++)
        if (under(canon, *w)) {
            snprintf(out, n, "%s%s", am_datadir, canon);
            return 0;
        }
    if (under(canon, "/dev")) {
        for (const char **d = devices; *d; d++)
            if (!strcmp(canon + 5, *d)) { snprintf(out, n, "/dev/%s", *d); return 0; }
        if (dev_lookup(canon)) { snprintf(out, n, "/dev/null"); return 0; }  // stat-able stand-in
        // The rest of /dev is a tmpfs: writable, and emptied at every start.
        snprintf(out, n, "%s%s", am_datadir, canon);
        return 0;
    }
    if (under(canon, "/proc") || under(canon, "/sys")) {
        // Not modelled yet beyond the magic links resolved in am_resolve.
        if (!strcmp(canon, "/proc") || !strcmp(canon, "/sys")) {
            snprintf(out, n, "%s%s", am_datadir, canon);
            return 0;
        }
        return AM_ERR(LINUX_ENOENT);
    }
    snprintf(out, n, "%s%s", am_root, canon);
    return 0;
}

// /proc's magic links: /proc/self, /proc/<pid>/exe, /proc/<pid>/fd/<n>.
static bool magic_link(const char *canon, char *target, size_t n) {
    am_proc *p = am_self->proc;
    if (!strcmp(canon, "/proc/self")) { snprintf(target, n, "/proc/%d", p->pid); return true; }
    if (!strcmp(canon, "/proc/thread-self")) {
        snprintf(target, n, "/proc/%d/task/%d", p->pid, am_self->tid);
        return true;
    }
    int pid, fd;
    char rest[16];
    if (sscanf(canon, "/proc/%d/%15s", &pid, rest) == 2 && pid == p->pid) {
        if (!strcmp(rest, "exe")) { snprintf(target, n, "%s", p->exe); return true; }
    }
    if (sscanf(canon, "/proc/%d/fd/%d", &pid, &fd) == 2 && pid == p->pid) {
        am_file *f = fd >= 0 && fd < AM_MAX_FDS ? p->fds[fd] : NULL;
        if (f && f->gpath) { snprintf(target, n, "%s", f->gpath); return true; }
    }
    return false;
}

static const char *base_dir(int dirfd) {
    if (dirfd == LINUX_AT_FDCWD) return am_self->proc->cwd;
    am_file *f = am_fd_get(dirfd);
    return f && f->gpath ? f->gpath : NULL;
}

// Walks gpath (relative to dirfd) component by component in the guest's namespace, following
// symlinks the way Linux would. canon receives the guest path, host the backing host path.
int am_resolve(int dirfd, const char *gpath, bool follow, char *host, size_t hostsz, char *canon, size_t canonsz) {
    char cur[4096] = "", pending[4096], link[4096], hp[4096];
    if (!gpath || !*gpath) return AM_ERR(LINUX_ENOENT);
    if (gpath[0] != '/') {
        const char *b = base_dir(dirfd);
        if (!b) return AM_ERR(LINUX_EBADF);
        snprintf(cur, sizeof cur, "%s", strcmp(b, "/") ? b : "");
    }
    snprintf(pending, sizeof pending, "%s", gpath);
    int links = 0;
    char *p = pending;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        char *e = strchr(p, '/');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        char name[256];
        if (len >= sizeof name) return AM_ERR(LINUX_ENAMETOOLONG);
        memcpy(name, p, len);
        name[len] = 0;
        p += len;
        bool last = true;
        for (char *q = p; *q; q++) if (*q != '/') { last = false; break; }
        if (!strcmp(name, ".")) continue;
        if (!strcmp(name, "..")) {
            char *s = strrchr(cur, '/');
            if (s) *s = 0;
            continue;
        }
        size_t cl = strlen(cur);
        if (cl + 1 + len >= sizeof cur) return AM_ERR(LINUX_ENAMETOOLONG);
        cur[cl] = '/';
        memcpy(cur + cl + 1, name, len + 1);
        if (last && !follow) break;

        ssize_t ln = -1;
        if (magic_link(cur, link, sizeof link)) {
            ln = strlen(link);
        } else {
            if (host_path(cur, hp, sizeof hp) < 0) {
                // /proc/<pid> and below exist only as the magic links they lead to.
                if (last || under(cur, "/proc")) continue;
                return AM_ERR(LINUX_ENOENT);
            }
            ln = readlink(hp, link, sizeof link - 1);
            if (ln >= 0) link[ln] = 0;
        }
        if (ln < 0) continue;
        if (++links > 40) return AM_ERR(LINUX_ELOOP);
        // Splice the link target in front of what is left.
        char rest[4096];
        snprintf(rest, sizeof rest, "%s", p);
        snprintf(pending, sizeof pending, "%s%s", link, rest);
        p = pending;
        if (link[0] == '/') cur[0] = 0;
        else { char *s = strrchr(cur, '/'); if (s) *s = 0; }
    }
    if (!cur[0]) strcpy(cur, "/");
    if (canon) snprintf(canon, canonsz, "%s", cur);
    if (host) return host_path(cur, host, hostsz);
    return 0;
}

// ---- fd table ----------------------------------------------------------------------------
void am_fs_init(am_proc *p) {
    strcpy(p->cwd, "/");
    p->umask = 022;
    for (int i = 0; i < 3; i++) {
        am_file *f = calloc(1, sizeof *f);
        f->refs = 1;
        f->hostfd = i;
        f->lflags = i ? LINUX_O_WRONLY : LINUX_O_RDONLY;
        f->gpath = strdup("/dev/tty");
        p->fds[i] = f;
    }
    // /dev starts empty, as the tmpfs it stands for.
    char hp[4096];
    snprintf(hp, sizeof hp, "rm -rf '%s/dev'", am_datadir);
    if (system(hp)) {}
    const char *dirs[] = {"/data", "/data/local/tmp", "/tmp", "/cache", "/dev", "/dev/socket",
                          "/proc", "/sys", "/linkerconfig", "/debug_ramdisk", "/mnt", "/metadata", NULL};
    for (const char **d = dirs; *d; d++) {
        snprintf(hp, sizeof hp, "%s%s", am_datadir, *d);
        char *s = hp + strlen(am_datadir);
        while ((s = strchr(s + 1, '/'))) { *s = 0; mkdir(hp, 0755); *s = '/'; }
        mkdir(hp, 0755);
    }
}

am_file *am_fd_get(int fd) {
    if (fd < 0 || fd >= AM_MAX_FDS) return NULL;
    return am_self->proc->fds[fd];
}

int am_fd_install(am_proc *p, am_file *f, int min, bool cloexec) {
    pthread_mutex_lock(&p->lock);
    for (int i = min; i < AM_MAX_FDS; i++)
        if (!p->fds[i]) {
            p->fds[i] = f;
            p->cloexec[i] = cloexec;
            pthread_mutex_unlock(&p->lock);
            return i;
        }
    pthread_mutex_unlock(&p->lock);
    return AM_ERR(LINUX_EMFILE);
}

void am_file_put(am_file *f) {
    if (!f) return;
    if (__atomic_sub_fetch(&f->refs, 1, __ATOMIC_ACQ_REL)) return;
    am_event_file_gone(f);
    if (f->ops && f->ops->release) f->ops->release(f);
    if (f->hostfd > 2) close(f->hostfd);
    free(f->gpath);
    free(f->dents);
    free(f);
}

am_file *am_file_new(int hostfd, int lflags, const char *gpath, const am_file_ops *ops, void *priv) {
    am_file *f = calloc(1, sizeof *f);
    f->refs = 1;
    f->hostfd = hostfd;
    f->lflags = lflags;
    f->gpath = gpath ? strdup(gpath) : NULL;
    f->ops = ops;
    f->priv = priv;
    return f;
}

static am_file *file_new(int hostfd, int lflags, const char *gpath) {
    return am_file_new(hostfd, lflags, gpath, NULL, NULL);
}

static int darwin_oflags(int l) {
    int d = 0;
    switch (l & 3) { case 0: d = O_RDONLY; break; case 1: d = O_WRONLY; break; default: d = O_RDWR; }
    if (l & LINUX_O_CREAT) d |= O_CREAT;
    if (l & LINUX_O_EXCL) d |= O_EXCL;
    if (l & LINUX_O_NOCTTY) d |= O_NOCTTY;
    if (l & LINUX_O_TRUNC) d |= O_TRUNC;
    if (l & LINUX_O_APPEND) d |= O_APPEND;
    if (l & LINUX_O_NONBLOCK) d |= O_NONBLOCK;
    if (l & LINUX_O_DIRECTORY) d |= O_DIRECTORY;
    if (l & LINUX_O_NOFOLLOW) d |= O_NOFOLLOW;
    if (l & LINUX_O_CLOEXEC) d |= O_CLOEXEC;
    if (l & LINUX_O_DSYNC) d |= O_DSYNC;
    return d;
}

// Executable mappings of a file need its code signature registered with the kernel first,
// which is what dyld does for every image it loads. Once per file; the kernel keeps it.
static void register_signature(int fd) {
    char h[AM_HEADER_SIZE];
    if (pread(fd, h, sizeof h, 0) != sizeof h) return;
    const struct mach_header_64 *mh = (const void *)h;
    const struct load_command *lc = (const void *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds && (const char *)lc < h + sizeof h; i++) {
        if (lc->cmd == LC_CODE_SIGNATURE) {
            const struct linkedit_data_command *cs = (const void *)lc;
            fsignatures_t fs = {.fs_file_start = 0, .fs_blob_start = (void *)(uintptr_t)cs->dataoff, .fs_blob_size = cs->datasize};
            fcntl(fd, F_ADDFILESIGS_RETURN, &fs);
            return;
        }
        lc = (const void *)((const char *)lc + lc->cmdsize);
    }
}

// Reads the andromach marker; a precompiled image shows the guest only its payload.
static void detect_image(am_file *f) {
    struct stat st;
    if (fstat(f->hostfd, &st) || !S_ISREG(st.st_mode) || st.st_size < AM_HEADER_SIZE) return;
    char m[32];
    if (pread(f->hostfd, m, sizeof m, AM_MARKER_OFF) != sizeof m) return;
    if (memcmp(m, AM_MARKER, sizeof AM_MARKER)) return;
    f->image = true;
    f->base = AM_HEADER_SIZE;
    memcpy(&f->size, m + 24, 8);
    register_signature(f->hostfd);
}

long am_open(const char *gpath, int dirfd, int lflags, int mode, am_file **out) {
    char host[4096], canon[4096];
    canon[0] = 0;
    int r = am_resolve(dirfd, gpath, !(lflags & LINUX_O_NOFOLLOW), host, sizeof host, canon, sizeof canon);
    if ((r == 0 || r == AM_ERR(LINUX_ENOENT)) && (under(canon, "/proc") || under(canon, "/sys")))
        return am_procfs_open(canon, lflags, out);
    if (r < 0) return r;
    am_dev_open_fn dev = dev_lookup(canon);
    if (dev) {
        r = dev(canon + 5, lflags, out);
        if (r == 0 && !(*out)->gpath) (*out)->gpath = strdup(canon);
        return r;
    }
    int fd;
    if (lflags & LINUX_O_PATH) {
        fd = open(host, O_RDONLY | O_CLOEXEC | ((lflags & LINUX_O_NOFOLLOW) ? O_SYMLINK : 0));
        if (fd < 0 && errno == EACCES) fd = open(host, O_SEARCH | O_CLOEXEC);
        if (fd < 0 && (errno == EOPNOTSUPP || errno == ENXIO)) {
            // A socket or fifo: an O_PATH fd only names it, so keep the name without a host fd.
            struct stat st;
            if (lstat(host, &st)) return am_errno(errno);
            *out = file_new(-1, lflags, canon);
            return 0;
        }
    } else {
        fd = open(host, darwin_oflags(lflags) | O_CLOEXEC, mode & ~am_self->proc->umask);
    }
    if (fd < 0) return am_errno(errno);
    am_file *f = file_new(fd, lflags, canon);
    detect_image(f);
    *out = f;
    return 0;
}

long am_pread(am_file *f, void *buf, size_t n, uint64_t off) {
    if (f->image) {
        if (off >= f->size) return 0;
        if (n > f->size - off) n = f->size - off;
        off += f->base;
    }
    ssize_t r = pread(f->hostfd, buf, n, off);
    return r < 0 ? am_errno(errno) : r;
}

// ---- stat --------------------------------------------------------------------------------
static void to_linux_stat(struct linux_stat *l, const struct stat *s, const am_file *img) {
    memset(l, 0, sizeof *l);
    l->st_dev = s->st_dev;
    l->st_ino = s->st_ino;
    l->st_mode = s->st_mode;
    l->st_nlink = s->st_nlink;
    // Everything belongs to root for now: the host's uid means nothing to the guest, and
    // bionic refuses property files that are not root's. Per-file ownership comes later.
    l->st_uid = 0;
    l->st_gid = 0;
    l->st_rdev = s->st_rdev;
    l->st_size = img ? (int64_t)img->size : s->st_size;
    l->st_blksize = s->st_blksize;
    l->st_blocks = s->st_blocks;
    l->st_atime_ = s->st_atimespec.tv_sec; l->st_atime_nsec = s->st_atimespec.tv_nsec;
    l->st_mtime_ = s->st_mtimespec.tv_sec; l->st_mtime_nsec = s->st_mtimespec.tv_nsec;
    l->st_ctime_ = s->st_ctimespec.tv_sec; l->st_ctime_nsec = s->st_ctimespec.tv_nsec;
}

// Host stat of a path, sized as the guest sees it when it is an image.
static long stat_path(const char *host, bool follow, struct linux_stat *out) {
    struct stat st;
    if ((follow ? stat : lstat)(host, &st)) return am_errno(errno);
    am_file probe = {0};
    if (S_ISREG(st.st_mode) && st.st_size >= AM_HEADER_SIZE) {
        probe.hostfd = open(host, O_RDONLY | O_CLOEXEC);
        if (probe.hostfd >= 0) { detect_image(&probe); close(probe.hostfd); }
    }
    to_linux_stat(out, &st, probe.image ? &probe : NULL);
    return 0;
}

static long do_fstat(am_file *f, struct linux_stat *out);

// /proc and /sys entries exist when they can be opened.
static long virtual_stat(const char *canon, struct linux_stat *out) {
    char target[4096];
    if (magic_link(canon, target, sizeof target)) {
        memset(out, 0, sizeof *out);
        out->st_mode = 0120777;  // S_IFLNK
        out->st_nlink = 1;
        out->st_size = strlen(target);
        return 0;
    }
    am_file *f;
    long r = am_procfs_open(canon, LINUX_O_RDONLY, &f);
    if (r < 0) return r;
    r = do_fstat(f, out);
    am_file_put(f);
    return r;
}

static long do_fstat(am_file *f, struct linux_stat *out) {
    struct stat st;
    if (f->hostfd < 0 && f->gpath) {
        char host[4096];
        long r = am_resolve(LINUX_AT_FDCWD, f->gpath, false, host, sizeof host, NULL, 0);
        return r < 0 ? r : stat_path(host, false, out);
    }
    if (fstat(f->hostfd, &st)) return am_errno(errno);
    to_linux_stat(out, &st, f->image ? f : NULL);
    return 0;
}

static long do_statx(int dirfd, const char *path, int flags, struct linux_statx *sx) {
    struct linux_stat st;
    long r;
    if ((flags & LINUX_AT_EMPTY_PATH) && (!path || !*path)) {
        am_file *f = am_fd_get(dirfd);
        if (!f) return AM_ERR(LINUX_EBADF);
        r = do_fstat(f, &st);
    } else {
        char host[4096], canon[4096];
        r = am_resolve(dirfd, path, !(flags & LINUX_AT_SYMLINK_NOFOLLOW), host, sizeof host, canon, sizeof canon);
        if (r < 0 && r != AM_ERR(LINUX_ENOENT)) return r;
        if (under(canon, "/proc") || under(canon, "/sys")) r = virtual_stat(canon, &st);
        else if (r == 0) r = stat_path(host, !(flags & LINUX_AT_SYMLINK_NOFOLLOW), &st);
    }
    if (r) return r;
    memset(sx, 0, sizeof *sx);
    sx->stx_mask = 0x7ff;
    sx->stx_blksize = st.st_blksize;
    sx->stx_nlink = st.st_nlink;
    sx->stx_uid = st.st_uid;
    sx->stx_gid = st.st_gid;
    sx->stx_mode = st.st_mode;
    sx->stx_ino = st.st_ino;
    sx->stx_size = st.st_size;
    sx->stx_blocks = st.st_blocks;
    sx->stx_atime.tv_sec = st.st_atime_; sx->stx_atime.tv_nsec = st.st_atime_nsec;
    sx->stx_mtime.tv_sec = st.st_mtime_; sx->stx_mtime.tv_nsec = st.st_mtime_nsec;
    sx->stx_ctime.tv_sec = st.st_ctime_; sx->stx_ctime.tv_nsec = st.st_ctime_nsec;
    sx->stx_btime = sx->stx_ctime;
    sx->stx_rdev_major = major(st.st_rdev); sx->stx_rdev_minor = minor(st.st_rdev);
    sx->stx_dev_major = major(st.st_dev); sx->stx_dev_minor = minor(st.st_dev);
    return 0;
}

// ---- directories -------------------------------------------------------------------------
static long getdents(am_file *f, uint8_t *buf, size_t n) {
    if (!f->dents) {
        // Read the whole directory once; Linux d_off cookies are then simple indexes.
        int dfd = dup(f->hostfd);
        DIR *d = fdopendir(dfd);
        if (!d) { close(dfd); return am_errno(errno); }
        rewinddir(d);
        size_t cap = 4096, len = 0;
        uint8_t *out = malloc(cap);
        struct dirent *e;
        while ((e = readdir(d))) {
            size_t nl = strlen(e->d_name);
            size_t rl = (19 + nl + 1 + 7) & ~7u;
            if (len + rl > cap) out = realloc(out, cap = (cap + rl) * 2);
            struct linux_dirent64 *ld = (void *)(out + len);
            ld->d_ino = e->d_ino;
            ld->d_off = len + rl;
            ld->d_reclen = rl;
            ld->d_type = e->d_type;  // DT_* values match
            memcpy(ld->d_name, e->d_name, nl + 1);
            len += rl;
        }
        closedir(d);
        f->dents = out;
        f->dents_len = len;
        f->dents_pos = 0;
    }
    size_t done = 0;
    while (f->dents_pos < f->dents_len) {
        struct linux_dirent64 *ld = (void *)((uint8_t *)f->dents + f->dents_pos);
        if (done + ld->d_reclen > n) break;
        memcpy(buf + done, ld, ld->d_reclen);
        done += ld->d_reclen;
        f->dents_pos += ld->d_reclen;
    }
    if (!done && f->dents_pos < f->dents_len) return AM_ERR(LINUX_EINVAL);
    return done;
}

// ---- terminals ---------------------------------------------------------------------------
static const struct { uint32_t l, d; } lflag_map[] = {
    {0x1, ISIG}, {0x2, ICANON}, {0x8, ECHO}, {0x10, ECHOE}, {0x20, ECHOK}, {0x40, ECHONL},
    {0x80, NOFLSH}, {0x100, TOSTOP}, {0x200, ECHOCTL}, {0x400, ECHOPRT}, {0x800, ECHOKE},
    {0x8000, IEXTEN}};
static const struct { uint32_t l, d; } iflag_map[] = {
    {0x1, IGNBRK}, {0x2, BRKINT}, {0x4, IGNPAR}, {0x8, PARMRK}, {0x10, INPCK}, {0x20, ISTRIP},
    {0x40, INLCR}, {0x80, IGNCR}, {0x100, ICRNL}, {0x400, IXON}, {0x800, IXANY},
    {0x1000, IXOFF}, {0x2000, IMAXBEL}, {0x4000, IUTF8}};
static const struct { uint32_t l, d; } oflag_map[] = {{0x1, OPOST}, {0x4, ONLCR}};
static const int cc_map[][2] = {  // Linux index, Darwin index
    {0, VINTR}, {1, VQUIT}, {2, VERASE}, {3, VKILL}, {4, VEOF}, {5, VTIME}, {6, VMIN},
    {8, VSTART}, {9, VSTOP}, {10, VSUSP}, {11, VEOL}, {12, VREPRINT}, {13, VDISCARD},
    {14, VWERASE}, {15, VLNEXT}, {16, VEOL2}};

#define MAPFLAGS(tbl, from, to, src) ({ uint64_t _o = 0; \
    for (size_t _i = 0; _i < sizeof tbl / sizeof *tbl; _i++) if ((src) & tbl[_i].from) _o |= tbl[_i].to; _o; })

static long do_ioctl(am_file *f, unsigned long req, uint64_t arg) {
    if (f->ops && f->ops->ioctl) return f->ops->ioctl(f, req, arg);
    int fd = f->hostfd;
    switch (req) {
    case LINUX_TCGETS: {
        struct termios t;
        if (tcgetattr(fd, &t)) return am_errno(errno);
        struct linux_termios *l = (void *)arg;
        memset(l, 0, sizeof *l);
        l->c_iflag = MAPFLAGS(iflag_map, d, l, t.c_iflag);
        l->c_oflag = MAPFLAGS(oflag_map, d, l, t.c_oflag);
        l->c_lflag = MAPFLAGS(lflag_map, d, l, t.c_lflag);
        l->c_cflag = 0x30 /*CS8*/ | 0x80 /*CREAD*/ | 0xF /*B38400*/;
        for (size_t i = 0; i < sizeof cc_map / sizeof *cc_map; i++) l->c_cc[cc_map[i][0]] = t.c_cc[cc_map[i][1]];
        return 0;
    }
    case LINUX_TCSETS: case LINUX_TCSETSW: case LINUX_TCSETSF: {
        struct termios t;
        if (tcgetattr(fd, &t)) return am_errno(errno);
        const struct linux_termios *l = (void *)arg;
        t.c_iflag = MAPFLAGS(iflag_map, l, d, l->c_iflag);
        t.c_oflag = MAPFLAGS(oflag_map, l, d, l->c_oflag);
        t.c_lflag = MAPFLAGS(lflag_map, l, d, l->c_lflag);
        for (size_t i = 0; i < sizeof cc_map / sizeof *cc_map; i++) t.c_cc[cc_map[i][1]] = l->c_cc[cc_map[i][0]];
        int how = req == LINUX_TCSETS ? TCSANOW : req == LINUX_TCSETSW ? TCSADRAIN : TCSAFLUSH;
        return tcsetattr(fd, how, &t) ? am_errno(errno) : 0;
    }
    case LINUX_TIOCGWINSZ: return ioctl(fd, TIOCGWINSZ, (void *)arg) ? am_errno(errno) : 0;
    case LINUX_TIOCSWINSZ: return ioctl(fd, TIOCSWINSZ, (void *)arg) ? am_errno(errno) : 0;
    case LINUX_FIONREAD: return ioctl(fd, FIONREAD, (void *)arg) ? am_errno(errno) : 0;
    case LINUX_FIONBIO: return ioctl(fd, FIONBIO, (void *)arg) ? am_errno(errno) : 0;
    case LINUX_TIOCGPGRP: *(int *)arg = am_self->proc->pid; return 0;
    case LINUX_TIOCSPGRP: return 0;
    }
    return isatty(fd) ? AM_ERR(LINUX_EINVAL) : AM_ERR(LINUX_ENOTTY);
}

// ---- system calls ------------------------------------------------------------------------
#define A(i) (c->x[i])
#define STR(i) ((const char *)c->x[i])

// Before a read or write that may block (pipes, sockets, terminals): wait for the host fd
// with residency let go, so other members of a memory group can run meanwhile.
static void wait_ready(am_file *f, short ev) {
    if (!am_self->proc->mg || f->hostfd < 0 || f->image) return;
    struct stat st;
    if (fstat(f->hostfd, &st) || S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) return;
    if (fcntl(f->hostfd, F_GETFL) & O_NONBLOCK) return;
    struct pollfd p = {f->hostfd, ev, 0};
    am_block_begin();
    poll(&p, 1, -1);  // a kick cuts it short; the read or write then does the waiting
    am_block_end();
}

static long close_fd(int fd) {
    am_proc *p = am_self->proc;
    pthread_mutex_lock(&p->lock);
    am_file *f = fd >= 0 && fd < AM_MAX_FDS ? p->fds[fd] : NULL;
    if (f) p->fds[fd] = NULL;
    pthread_mutex_unlock(&p->lock);
    if (!f) return AM_ERR(LINUX_EBADF);
    am_file_put(f);
    return 0;
}

static long dup_to(int old, int new, bool cloexec) {
    am_proc *p = am_self->proc;
    am_file *f = am_fd_get(old);
    if (!f || new < 0 || new >= AM_MAX_FDS) return AM_ERR(LINUX_EBADF);
    if (old == new) return new;
    __atomic_add_fetch(&f->refs, 1, __ATOMIC_ACQ_REL);
    pthread_mutex_lock(&p->lock);
    am_file *prev = p->fds[new];
    p->fds[new] = f;
    p->cloexec[new] = cloexec;
    pthread_mutex_unlock(&p->lock);
    if (prev) am_file_put(prev);
    return new;
}

static int lflags_from_darwin(int d, int keep) {
    int l = keep & (3 | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW | LINUX_O_PATH);
    if (d & O_APPEND) l |= LINUX_O_APPEND;
    if (d & O_NONBLOCK) l |= LINUX_O_NONBLOCK;
    return l;
}

static long sys_fcntl(int fd, int cmd, uint64_t arg) {
    am_file *f = am_fd_get(fd);
    if (!f) return AM_ERR(LINUX_EBADF);
    am_proc *p = am_self->proc;
    switch (cmd) {
    case LINUX_F_DUPFD: case LINUX_F_DUPFD_CLOEXEC:
        __atomic_add_fetch(&f->refs, 1, __ATOMIC_ACQ_REL);
        {
            long r = am_fd_install(p, f, (int)arg, cmd == LINUX_F_DUPFD_CLOEXEC);
            if (r < 0) am_file_put(f);
            return r;
        }
    case LINUX_F_GETFD: return p->cloexec[fd] ? 1 : 0;
    case LINUX_F_SETFD: p->cloexec[fd] = arg & 1; return 0;
    case LINUX_F_GETFL: {
        if (f->hostfd < 0) return f->lflags;
        int d = fcntl(f->hostfd, F_GETFL);
        return d < 0 ? am_errno(errno) : lflags_from_darwin(d, f->lflags);
    }
    case LINUX_F_SETFL: {
        int d = fcntl(f->hostfd, F_GETFL);
        d &= ~(O_APPEND | O_NONBLOCK);
        if (arg & LINUX_O_APPEND) d |= O_APPEND;
        if (arg & LINUX_O_NONBLOCK) d |= O_NONBLOCK;
        if (fcntl(f->hostfd, F_SETFL, d)) return am_errno(errno);
        f->lflags = (f->lflags & ~(LINUX_O_APPEND | LINUX_O_NONBLOCK)) | (arg & (LINUX_O_APPEND | LINUX_O_NONBLOCK));
        return 0;
    }
    case LINUX_F_GETLK: case LINUX_F_SETLK: case LINUX_F_SETLKW:
    case LINUX_F_OFD_GETLK: case LINUX_F_OFD_SETLK: case LINUX_F_OFD_SETLKW:
        if (cmd == LINUX_F_GETLK || cmd == LINUX_F_OFD_GETLK) ((struct linux_flock *)arg)->l_type = 2; // F_UNLCK
        return 0;  // one guest owns the files; advisory locks always succeed
    case LINUX_F_SETPIPE_SZ: case LINUX_F_GETPIPE_SZ: return 65536;
    case LINUX_F_ADD_SEALS: case LINUX_F_GET_SEALS: return 0;
    }
    return AM_ERR(LINUX_EINVAL);
}

static long sys_ppoll(struct pollfd *g, unsigned n, const struct linux_timespec *ts) {
    struct pollfd h[n ? n : 1];
    for (unsigned i = 0; i < n; i++) {
        am_file *f = am_fd_get(g[i].fd);
        h[i].fd = g[i].fd < 0 ? -1 : f ? f->hostfd : -2;
        h[i].events = g[i].events & 0x3F;
        if (g[i].events & 0x100) h[i].events |= POLLWRNORM;
        if (g[i].events & 0x200) h[i].events |= POLLWRBAND;
        if (g[i].events & 0x80) h[i].events |= POLLRDBAND;
        h[i].revents = 0;
    }
    int bad = 0;
    for (unsigned i = 0; i < n; i++) if (h[i].fd == -2) { h[i].fd = -1; bad = 1; }
    int ms = ts ? (int)(ts->tv_sec * 1000 + (ts->tv_nsec + 999999) / 1000000) : -1;
    if (!bad && ms) am_block_begin();
    int r = poll(h, n, bad ? 0 : ms);
    if (!bad && ms) am_block_end();
    if (r < 0) return am_errno(errno);
    r = 0;
    for (unsigned i = 0; i < n; i++) {
        short re = h[i].revents & 0x3F;
        if (h[i].revents & POLLWRBAND) re |= 0x200;
        if (h[i].revents & POLLRDBAND) re |= 0x80;
        if (g[i].fd >= 0 && !am_fd_get(g[i].fd)) re = 0x20;  // POLLNVAL
        g[i].revents = re & (g[i].events | 0x38);
        if (g[i].revents) r++;
    }
    return r;
}

long sys_fs(am_ctx *c, long nr, bool *handled) {
    *handled = true;
    am_proc *p = am_self->proc;
    am_file *f;
    char host[4096], host2[4096];
    long r;
    switch (nr) {
    case LINUX_SYS_openat: {
        r = am_open(STR(1), (int)A(0), (int)A(2), (int)A(3), &f);
        if (r < 0) return r;
        r = am_fd_install(p, f, 0, A(2) & LINUX_O_CLOEXEC);
        if (r < 0) am_file_put(f);
        return r;
    }
    case LINUX_SYS_close: return close_fd((int)A(0));
    case LINUX_SYS_read:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        if (f->ops && f->ops->read) return f->ops->read(f, (void *)A(1), A(2));
        if (f->image) { r = am_pread(f, (void *)A(1), A(2), f->pos); if (r > 0) f->pos += r; return r; }
        wait_ready(f, POLLIN);
        r = read(f->hostfd, (void *)A(1), A(2));
        return r < 0 ? am_errno(errno) : r;
    case LINUX_SYS_write:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        if (f->ops && f->ops->write) return f->ops->write(f, (void *)A(1), A(2));
        wait_ready(f, POLLOUT);
        r = write(f->hostfd, (void *)A(1), A(2));
        return r < 0 ? am_errno(errno) : r;
    case LINUX_SYS_readv: case LINUX_SYS_writev:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        if (f->ops && nr == LINUX_SYS_readv && f->ops->readv) return f->ops->readv(f, (void *)A(1), (int)A(2));
        if (f->ops && nr == LINUX_SYS_writev && f->ops->writev) return f->ops->writev(f, (void *)A(1), (int)A(2));
        if (f->ops && (nr == LINUX_SYS_readv ? (void *)f->ops->read : (void *)f->ops->write)) {
            const struct iovec *iov = (void *)A(1);
            long total = 0;
            for (int i = 0; i < (int)A(2); i++) {
                r = nr == LINUX_SYS_readv ? f->ops->read(f, iov[i].iov_base, iov[i].iov_len)
                                          : f->ops->write(f, iov[i].iov_base, iov[i].iov_len);
                if (r < 0) return total ? total : r;
                total += r;
                if ((size_t)r < iov[i].iov_len) break;
            }
            return total;
        }
        if (f->image && nr == LINUX_SYS_readv) {
            struct iovec *iov = (void *)A(1);
            long total = 0;
            for (int i = 0; i < (int)A(2); i++) {
                r = am_pread(f, iov[i].iov_base, iov[i].iov_len, f->pos);
                if (r < 0) return total ? total : r;
                f->pos += r; total += r;
                if ((size_t)r < iov[i].iov_len) break;
            }
            return total;
        }
        r = nr == LINUX_SYS_readv ? readv(f->hostfd, (void *)A(1), (int)A(2)) : writev(f->hostfd, (void *)A(1), (int)A(2));
        return r < 0 ? am_errno(errno) : r;
    case LINUX_SYS_pread64:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        return am_pread(f, (void *)A(1), A(2), A(3));
    case LINUX_SYS_pwrite64:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        r = pwrite(f->hostfd, (void *)A(1), A(2), A(3));
        return r < 0 ? am_errno(errno) : r;
    case LINUX_SYS_lseek:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        if (f->image) {
            int64_t base = A(2) == 0 ? 0 : A(2) == 1 ? (int64_t)f->pos : (int64_t)f->size;
            int64_t to = base + (int64_t)A(1);
            if (to < 0) return AM_ERR(LINUX_EINVAL);
            return f->pos = to;
        }
        if (f->dents && A(1) == 0 && A(2) == 0) { f->dents_pos = 0; free(f->dents); f->dents = NULL; }
        r = lseek(f->hostfd, (off_t)A(1), (int)A(2));
        return r < 0 ? am_errno(errno) : r;
    case LINUX_SYS_newfstatat:
        if ((A(3) & LINUX_AT_EMPTY_PATH) && !*STR(1)) {
            if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
            return do_fstat(f, (void *)A(2));
        }
        {
            char canon[4096];
            r = am_resolve((int)A(0), STR(1), !(A(3) & LINUX_AT_SYMLINK_NOFOLLOW), host, sizeof host, canon, sizeof canon);
            if (under(canon, "/proc") || under(canon, "/sys")) return virtual_stat(canon, (void *)A(2));
            return r < 0 ? r : stat_path(host, !(A(3) & LINUX_AT_SYMLINK_NOFOLLOW), (void *)A(2));
        }
    case LINUX_SYS_fstat:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        return do_fstat(f, (void *)A(1));
    case LINUX_SYS_statx: return do_statx((int)A(0), STR(1), (int)A(2), (void *)A(4));
    case LINUX_SYS_readlinkat: {
        char canon[4096], target[4096];
        r = am_resolve((int)A(0), STR(1), false, host, sizeof host, canon, sizeof canon);
        ssize_t n;
        if (magic_link(canon, target, sizeof target)) n = strlen(target);
        else if (r < 0) return r;
        else if ((n = readlink(host, target, sizeof target)) < 0) return am_errno(errno);
        if ((size_t)n > A(3)) n = A(3);
        memcpy((void *)A(2), target, n);
        return n;
    }
    case LINUX_SYS_faccessat: case LINUX_SYS_faccessat2:
        {
            char canon[4096];
            r = am_resolve((int)A(0), STR(1), !(nr == LINUX_SYS_faccessat2 && (A(3) & LINUX_AT_SYMLINK_NOFOLLOW)),
                           host, sizeof host, canon, sizeof canon);
            if (under(canon, "/proc") || under(canon, "/sys")) {
                struct linux_stat st;
                return virtual_stat(canon, &st);
            }
        }
        if (r < 0) return r;
        return access(host, (int)A(2) & 7) ? am_errno(errno) : 0;
    case LINUX_SYS_getdents64:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        return getdents(f, (void *)A(1), A(2));
    case LINUX_SYS_getcwd: {
        size_t n = strlen(p->cwd) + 1;
        if (n > A(1)) return AM_ERR(LINUX_ERANGE);
        memcpy((void *)A(0), p->cwd, n);
        return n;
    }
    case LINUX_SYS_chdir: case LINUX_SYS_fchdir: {
        char canon[4096];
        if (nr == LINUX_SYS_chdir) r = am_resolve(LINUX_AT_FDCWD, STR(0), true, host, sizeof host, canon, sizeof canon);
        else if (!(f = am_fd_get((int)A(0))) || !f->gpath) return AM_ERR(LINUX_EBADF);
        else r = am_resolve(LINUX_AT_FDCWD, f->gpath, true, host, sizeof host, canon, sizeof canon);
        if (r < 0) return r;
        struct stat st;
        if (stat(host, &st)) return am_errno(errno);
        if (!S_ISDIR(st.st_mode)) return AM_ERR(LINUX_ENOTDIR);
        snprintf(p->cwd, sizeof p->cwd, "%s", canon);
        return 0;
    }
    case LINUX_SYS_mkdirat:
        r = am_resolve((int)A(0), STR(1), false, host, sizeof host, NULL, 0);
        return r < 0 ? r : mkdir(host, (mode_t)A(2) & ~p->umask) ? am_errno(errno) : 0;
    case LINUX_SYS_unlinkat:
        r = am_resolve((int)A(0), STR(1), false, host, sizeof host, NULL, 0);
        if (r < 0) return r;
        return ((A(2) & LINUX_AT_REMOVEDIR) ? rmdir(host) : unlink(host)) ? am_errno(errno) : 0;
    case LINUX_SYS_renameat: case LINUX_SYS_renameat2:
        r = am_resolve((int)A(0), STR(1), false, host, sizeof host, NULL, 0);
        if (r == 0) r = am_resolve((int)A(2), STR(3), false, host2, sizeof host2, NULL, 0);
        return r < 0 ? r : rename(host, host2) ? am_errno(errno) : 0;
    case LINUX_SYS_symlinkat:
        r = am_resolve((int)A(1), STR(2), false, host, sizeof host, NULL, 0);
        return r < 0 ? r : symlink(STR(0), host) ? am_errno(errno) : 0;
    case LINUX_SYS_linkat:
        r = am_resolve((int)A(0), STR(1), false, host, sizeof host, NULL, 0);
        if (r == 0) r = am_resolve((int)A(2), STR(3), false, host2, sizeof host2, NULL, 0);
        return r < 0 ? r : link(host, host2) ? am_errno(errno) : 0;
    case LINUX_SYS_fchmodat:
        r = am_resolve((int)A(0), STR(1), true, host, sizeof host, NULL, 0);
        return r < 0 ? r : chmod(host, (mode_t)A(2)) ? am_errno(errno) : 0;
    case LINUX_SYS_fchmod:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        if (f->hostfd < 0 && f->gpath) {
            r = am_resolve(LINUX_AT_FDCWD, f->gpath, false, host, sizeof host, NULL, 0);
            return r < 0 ? r : chmod(host, (mode_t)A(1)) ? am_errno(errno) : 0;
        }
        return fchmod(f->hostfd, (mode_t)A(1)) ? am_errno(errno) : 0;
    case LINUX_SYS_fchownat: case LINUX_SYS_fchown:
        return 0;  // one user on the host; ownership is not modelled
    case LINUX_SYS_utimensat: {
        const struct timespec *ts = (void *)A(2);
        if (!A(1)) {
            if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
            return futimens(f->hostfd, ts) ? am_errno(errno) : 0;
        }
        r = am_resolve((int)A(0), STR(1), !(A(3) & LINUX_AT_SYMLINK_NOFOLLOW), host, sizeof host, NULL, 0);
        return r < 0 ? r : utimensat(AT_FDCWD, host, ts, (A(3) & LINUX_AT_SYMLINK_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0) ? am_errno(errno) : 0;
    }
    case LINUX_SYS_ftruncate:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        return ftruncate(f->hostfd, (off_t)A(1)) ? am_errno(errno) : 0;
    case LINUX_SYS_truncate:
        r = am_resolve(LINUX_AT_FDCWD, STR(0), true, host, sizeof host, NULL, 0);
        return r < 0 ? r : truncate(host, (off_t)A(1)) ? am_errno(errno) : 0;
    case LINUX_SYS_fsync: case LINUX_SYS_fdatasync:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        return fsync(f->hostfd) ? am_errno(errno) : 0;
    case LINUX_SYS_sync: case LINUX_SYS_syncfs: return 0;
    case LINUX_SYS_statfs: case LINUX_SYS_fstatfs: {
        struct statfs s;
        if (nr == LINUX_SYS_statfs) {
            r = am_resolve(LINUX_AT_FDCWD, STR(0), true, host, sizeof host, NULL, 0);
            if (r < 0) return r;
            if (statfs(host, &s)) return am_errno(errno);
        } else {
            if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
            if (fstatfs(f->hostfd, &s)) return am_errno(errno);
        }
        struct linux_statfs *l = (void *)A(1);
        memset(l, 0, sizeof *l);
        const char *gp = nr == LINUX_SYS_statfs ? STR(0) : f->gpath ? f->gpath : "";
        l->f_type = under(gp, "/sys/fs/selinux") ? 0xF97CFF8C : under(gp, "/proc") ? 0x9FA0
                  : under(gp, "/sys") ? 0x62656572 : 0xEF53;  // selinuxfs, proc, sysfs, ext4
        l->f_bsize = s.f_bsize; l->f_blocks = s.f_blocks; l->f_bfree = s.f_bfree;
        l->f_bavail = s.f_bavail; l->f_files = s.f_files; l->f_ffree = s.f_ffree;
        l->f_namelen = 255; l->f_frsize = s.f_bsize;
        return 0;
    }
    case LINUX_SYS_dup:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        __atomic_add_fetch(&f->refs, 1, __ATOMIC_ACQ_REL);
        r = am_fd_install(p, f, 0, false);
        if (r < 0) am_file_put(f);
        return r;
    case LINUX_SYS_dup3:
        if (A(0) == A(1)) return AM_ERR(LINUX_EINVAL);
        return dup_to((int)A(0), (int)A(1), A(2) & LINUX_O_CLOEXEC);
    case LINUX_SYS_fcntl: return sys_fcntl((int)A(0), (int)A(1), A(2));
    case LINUX_SYS_ioctl:
        if (!(f = am_fd_get((int)A(0)))) return AM_ERR(LINUX_EBADF);
        return do_ioctl(f, A(1), A(2));
    case LINUX_SYS_flock: return 0;
    case LINUX_SYS_pipe2: {
        int h[2];
        if (pipe(h)) return am_errno(errno);
        int *out = (int *)A(0);
        for (int i = 0; i < 2; i++) {
            fcntl(h[i], F_SETFD, FD_CLOEXEC);
            if (A(1) & LINUX_O_NONBLOCK) fcntl(h[i], F_SETFL, O_NONBLOCK);
            out[i] = am_fd_install(p, file_new(h[i], i ? LINUX_O_WRONLY : LINUX_O_RDONLY, "pipe:"), 0, A(1) & LINUX_O_CLOEXEC);
        }
        return 0;
    }
    case LINUX_SYS_ppoll: return sys_ppoll((void *)A(0), (unsigned)A(1), (void *)A(2));
    case LINUX_SYS_umask: { uint32_t o = p->umask; p->umask = A(0) & 0777; return o; }
    case LINUX_SYS_sendfile: {
        am_file *out = am_fd_get((int)A(0)), *in = am_fd_get((int)A(1));
        if (!out || !in) return AM_ERR(LINUX_EBADF);
        int64_t *offp = (void *)A(2);
        uint64_t off = offp ? (uint64_t)*offp : in->image ? in->pos : (uint64_t)lseek(in->hostfd, 0, SEEK_CUR);
        char buf[65536];
        long done = 0;
        while ((uint64_t)done < A(3)) {
            size_t want = A(3) - done < sizeof buf ? A(3) - done : sizeof buf;
            long n = am_pread(in, buf, want, off);
            if (n <= 0) break;
            ssize_t w = write(out->hostfd, buf, n);
            if (w <= 0) break;
            done += w; off += w;
        }
        if (offp) *offp = off;
        else if (in->image) in->pos = off;
        else lseek(in->hostfd, off, SEEK_SET);
        return done;
    }
    }
    *handled = false;
    return 0;
}
