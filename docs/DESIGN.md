# Design

## The constraint

iOS runs only machine code that comes from a signed file. A process cannot make writable
memory executable, so there is no JIT, and it cannot run an unsigned page. Third-party apps also
get no `fork`, no `exec`, no hypervisor and no kernel extension.

Android arm64 code already runs on the iPhone's CPU, because both use the same instruction set.
What it cannot do is talk to Linux, and it cannot be loaded from files Apple has not signed.
andromach therefore does two things:

1. **Precompile** every ELF file into a signed image at build time (`tools/amc.py`).
2. **Be the kernel**: implement the Linux system calls inside the app (`runtime/`).

## Images

An image is the ELF file, rewritten, inside a Mach-O wrapper:

```
[0, 0x4000)           Mach-O header + load commands; andromach marker at 0x3000
[0x4000, 0x4000+P)    payload: the rewritten ELF file, then a stub segment
[0x4000+P, ...)       __LINKEDIT with the code signature
```

The runtime shows the guest only the payload, so `open`, `read`, `fstat` and `mmap` behave as
they would on the original ELF file. Android's `linker64` loads every shared library itself and
maps them wherever it likes. Signatures cover page contents, not addresses, so signed code stays
valid at any address. Before the first executable mapping of an image, the runtime registers the
image's signature with the kernel (`fcntl(F_ADDFILESIGS_RETURN)`), as dyld does for dylibs. A
16 KiB page size is used throughout: Android 15+ images are already 16 KiB aligned, which matches
iOS.

### What gets rewritten

Three kinds of instruction cannot run as written on Darwin:

| Instruction | Why it breaks | Becomes |
|---|---|---|
| `svc #0` | Darwin would take x16 as a Darwin syscall number | branch to a syscall stub |
| `mrs xN, tpidr_el0` | Darwin uses TPIDR_EL0 for the CPU number and does not preserve it | branch to a TLS stub |
| `msr tpidr_el0, xN` | the same | `brk` trap (rare: once per thread) |

The stubs live in a new `PT_LOAD` segment appended after the last one. It is made from a
`PT_NOTE` program header, which the dynamic linker does not need. A stub reaches the runtime
through Darwin's per-thread data: `TPIDRRO_EL0` holds the TSD base, and andromach uses two slots
libpthread reserves and leaves unused (110 and 111, the old ObjC GC keys):

```
TLS read:  mrs xN, tpidrro_el0 ; ldr xN, [xN, #110*8] ; b back
syscall:   stp x16, x30, [sp, #-16]! ; mrs x16, tpidrro_el0 ; ldr x16, [x16, #111*8]
           blr x16 ; ldp x16, x30, [sp], #16 ; b back
```

`am_syscall_entry` (`runtime/entry.S`) saves every register, vectors and flags included, because
Linux preserves all of them except x0. Where a stub cannot be used (no `PT_NOTE`, or out of
branch range), the instruction becomes `brk #0xA5xx` and the SIGTRAP handler does the same work
from the signal context.

Code that checks its own bytes has to be told about the rewrite. So far that is BoringSSL's FIPS
module: amc recomputes its HMAC over the rewritten code and replaces the stored value.

Darwin also zeroes x18 on context switch. The Android userland seen so far does not use x18 (no
shadow call stack in user space), but amc should check for it.

## Runtime

The guest and the runtime share one Darwin process and one address space. Guest memory is
ordinary host memory; guest threads are pthreads.

- **Files** (`fs.c`): the guest's paths are resolved component by component in its own namespace,
  following its symlinks (`/system/bin/linker64 -> /apex/...`). The read-only root comes from the
  app bundle, `/data`, `/tmp` and `/dev/socket` from a writable directory, and `/dev` from a
  whitelist of host devices. Each process has its own fd table.
- **Memory** (`mm.c`): `mmap` maps host memory directly. `MADV_DONTNEED` zero-fills, as Linux
  does. With `--deny-exec` (the iOS rule), an executable mapping must come from an image.
- **Threads** (`thread.c`): `clone(CLONE_THREAD)` makes a pthread that resumes the guest on its
  new stack with its TLS slot set. `futex` maps onto `os_sync_wait_on_address`.
- **Context switches** (`am_resume`): installing a whole register state (new thread, signal
  delivery, `rt_sigreturn`) traps once and lets the kernel restore it from the signal frame.

### Processes (next)

iOS has no `fork`. Android processes become separate guests in the one address space. Each has
its own fd table, signal state and pid, and its own copy of every library's data, because each
`linker64` instance maps its own data segments. The code pages are shared. Two cases need care:

- `fork` + `exec` (shells, `system()`): the child runs as a new guest from the `exec`.
- Zygote, which forks without `exec`: replaced by starting each app process fresh, the way
  `app_process` and `--invoke-with` already can. Startup is slower; precompiled boot images
  offset most of that.

## ART and apps

ART runs with the JIT off. Everything that runs natively is compiled ahead of time: the boot
image and the preinstalled apps go through `dex2oat` on the build machine, and their `.oat` and
`.odex` files are ELF files like any other, so amc turns them into images. Apps installed at run
time run in ART's interpreter (nterp). They work, but more slowly.

## Editions

One runtime, two builds of the root:

- **Lite**: the Android core plus a small set of preinstalled apps. A size that suits the App
  Store and a phone's storage.
- **Full**: a large set of preinstalled apps, all precompiled.

The difference is a list of APKs per edition. Each is precompiled at build time and lands in the
bundle as signed images.

## Graphics (planned)

The emulator image already sends its GPU work off the guest: GLES and Vulkan calls are
serialized to the host (gfxstream / goldfish pipe). The plan is to implement that host side
inside the app over Metal (through ANGLE and MoltenVK). The guest image can then stay unchanged,
with SurfaceFlinger composing into a CAMetalLayer.
