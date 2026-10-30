// Memory system calls. The guest and the runtime share one Darwin address space; guest mappings
// are ordinary host mappings. Executable mappings come only from precompiled image files, which
// is the one rule iOS imposes on the guest.
#include "am.h"
#include "linux.h"
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int host_prot(int p) {
    return (p & LINUX_PROT_READ ? PROT_READ : 0) | (p & LINUX_PROT_WRITE ? PROT_WRITE : 0) |
           (p & LINUX_PROT_EXEC ? PROT_EXEC : 0);
}

long am_mmap(uint64_t addr, uint64_t len, int prot, int flags, int fd, uint64_t off) {
    if (!len) return AM_ERR(LINUX_EINVAL);
    int hflags = (flags & LINUX_MAP_SHARED) ? MAP_SHARED : MAP_PRIVATE;
    bool fixed = flags & LINUX_MAP_FIXED, noreplace = flags & LINUX_MAP_FIXED_NOREPLACE;
    if (fixed) hflags |= MAP_FIXED;
    if (flags & LINUX_MAP_NORESERVE) hflags |= MAP_NORESERVE;
    int hfd = -1;
    am_file *f = NULL;
    if (flags & LINUX_MAP_ANONYMOUS) {
        hflags |= MAP_ANON;
        off = 0;
        if ((prot & LINUX_PROT_EXEC) && am_deny_exec) return AM_ERR(LINUX_EACCES);
    } else {
        if (!(f = am_fd_get(fd))) return AM_ERR(LINUX_EBADF);
        if (f->ops && f->ops->mmap) return f->ops->mmap(f, addr, len, prot, flags, off);
        if ((prot & LINUX_PROT_EXEC) && am_deny_exec && !f->image) return AM_ERR(LINUX_EACCES);
        hfd = f->hostfd;
        if (f->image) off += f->base;
        if (off % AM_PAGE) {
            // Not host-page aligned: only a private, non-executable copy can be made.
            if ((flags & LINUX_MAP_SHARED) || (prot & LINUX_PROT_EXEC)) return AM_ERR(LINUX_EINVAL);
            void *m = mmap((void *)addr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | (fixed ? MAP_FIXED : 0), -1, 0);
            if (m == MAP_FAILED) return am_errno(errno);
            ssize_t n = pread(hfd, m, len, off);
            (void)n;
            mprotect(m, len, host_prot(prot));
            return (long)m;
        }
    }
    void *m = mmap((void *)addr, len, host_prot(prot), hflags, hfd, off);
    if (m == MAP_FAILED) return am_errno(errno);
    if (noreplace && !fixed && (uint64_t)m != addr) {
        munmap(m, len);
        return AM_ERR(LINUX_EEXIST);
    }
    return (long)m;
}

// Linux MADV_DONTNEED zero-fills private anonymous pages; Darwin's only drops them lazily, so
// replace such ranges with fresh zero pages.
static long dontneed(uint64_t addr, uint64_t len) {
    mach_vm_address_t a = addr;
    uint64_t end = addr + len;
    while (a < end) {
        mach_vm_size_t sz;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj;
        mach_vm_address_t r = a;
        if (mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj))
            break;
        if (r >= end) break;
        uint64_t s = r > a ? r : a, e = r + sz < end ? r + sz : end;
        if (!(info.protection & VM_PROT_EXECUTE) && !info.shared && (info.protection & VM_PROT_WRITE))
            mmap((void *)s, e - s, info.protection & 3, MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0);
        a = e;
    }
    return 0;
}

#define A(i) (c->x[i])

long sys_mm(am_ctx *c, long nr, bool *handled) {
    *handled = true;
    switch (nr) {
    case LINUX_SYS_mmap: return am_mmap(A(0), A(1), (int)A(2), (int)A(3), (int)A(4), A(5));
    case LINUX_SYS_munmap: return munmap((void *)A(0), A(1)) ? am_errno(errno) : 0;
    case LINUX_SYS_mprotect:
        if ((A(2) & LINUX_PROT_EXEC) && am_deny_exec) {
            // Keeping code executable is fine (RELRO, re-protecting mapped segments); making
            // data executable is what iOS refuses.
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj;
            mach_vm_address_t r = A(0);
            mach_vm_size_t sz;
            if (mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) ||
                !(info.max_protection & VM_PROT_EXECUTE))
                return AM_ERR(LINUX_EACCES);
        }
        return mprotect((void *)A(0), A(1), host_prot((int)A(2))) ? am_errno(errno) : 0;
    case LINUX_SYS_madvise:
        if (A(2) == LINUX_MADV_DONTNEED) return dontneed(A(0), A(1));
        return 0;
    case LINUX_SYS_mremap: {
        uint64_t old = A(0), oldsz = A(1), newsz = A(2), flags = A(3);
        if (newsz <= oldsz) {
            if (newsz < oldsz) munmap((void *)(old + newsz), oldsz - newsz);
            return old;
        }
        if (!(flags & LINUX_MREMAP_MAYMOVE)) return AM_ERR(LINUX_ENOMEM);
        // Move by remapping the same pages, which keeps shared and file mappings shared.
        mach_vm_address_t to = (flags & LINUX_MREMAP_FIXED) ? A(4) : 0;
        vm_prot_t cur, max;
        kern_return_t kr = mach_vm_remap(mach_task_self(), &to, oldsz, 0,
                                         (flags & LINUX_MREMAP_FIXED) ? VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE : VM_FLAGS_ANYWHERE,
                                         mach_task_self(), old, false, &cur, &max, VM_INHERIT_DEFAULT);
        if (kr) return AM_ERR(LINUX_ENOMEM);
        // Grow in place after the moved pages if possible, else move again into a larger hole.
        void *tail = mmap((void *)(to + oldsz), newsz - oldsz, cur & 3, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (tail != (void *)(to + oldsz)) {
            if (tail != MAP_FAILED) munmap(tail, newsz - oldsz);
            void *big = mmap(NULL, newsz, cur & 3, MAP_PRIVATE | MAP_ANON, -1, 0);
            if (big == MAP_FAILED) { munmap((void *)to, oldsz); return AM_ERR(LINUX_ENOMEM); }
            mach_vm_address_t b = (mach_vm_address_t)big;
            mach_vm_remap(mach_task_self(), &b, oldsz, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                          mach_task_self(), to, false, &cur, &max, VM_INHERIT_DEFAULT);
            munmap((void *)to, oldsz);
            to = b;
        }
        munmap((void *)old, oldsz);
        return to;
    }
    case LINUX_SYS_brk: return 0;  // no heap break; bionic allocates with mmap
    case LINUX_SYS_msync: return msync((void *)A(0), A(1), MS_SYNC) ? am_errno(errno) : 0;
    case LINUX_SYS_mincore: {
        uint8_t *vec = (void *)A(2);
        size_t n = (A(1) + AM_PAGE - 1) / AM_PAGE;
        memset(vec, 1, n);
        return 0;
    }
    case LINUX_SYS_mlock: case LINUX_SYS_munlock: case LINUX_SYS_mlock2: return 0;
    }
    *handled = false;
    return 0;
}
