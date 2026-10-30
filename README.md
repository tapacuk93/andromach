# andromach

**Android, precompiled into an iOS app.** andromach runs the real Android userland (Google's
arm64 system image: bionic, the dynamic linker, native daemons, ART and the framework) natively
on an iPhone's CPU. It does not emulate anything.

An iPhone and an Android phone use the same instruction set. What differs is the kernel beneath
the code, and iOS's rule that only signed code may run. andromach handles each:

- **The kernel:** a runtime inside the app implements the Linux system calls on top of Darwin.
- **Signed code only:** every Android binary is precompiled at build time into a signed image
  the app ships. Android's own linker maps those images at runtime as if they were ordinary ELF
  files. No JIT and no unsigned page is ever needed.

```
 build time (Mac)                                  run time (iPhone)
 ┌──────────────────────────┐                      ┌───────────────────────────────────────┐
 │ Android system image     │                      │ andromach.app                         │
 │  system, vendor, APEXes  │    amc: rewrite      │  ┌─────────────────────────────────┐  │
 │  arm64 ELF files ────────┼──► svc/TLS instrs,   │  │ Android userland, unmodified    │  │
 │                          │    wrap in signed    │  │  linker64 · bionic · ART · apps │  │
 │ preinstalled apps        │    Mach-O images ───►│  └──────────────┬──────────────────┘  │
 │  dex2oat ahead of time ──┼──────────────────────┼──►  stubs / traps │ Linux syscalls    │
 └──────────────────────────┘                      │  ┌──────────────▼──────────────────┐  │
                                                   │  │ andromach runtime (Linux ABI)   │  │
                                                   │  └──────────────┬──────────────────┘  │
                                                   │            Darwin / XNU               │
                                                   └───────────────────────────────────────┘
```

## Status

Early, but the core works. On an Apple Silicon Mac, `amrun` runs Android 17's `linker64`,
bionic, `toybox` and `mksh` from precompiled, code-signed images. It also enforces the iOS rule:
nothing runs from memory that did not come from a signed image.

```
$ build/amrun --deny-exec -r build/root /system/bin/toybox uname -a
Linux localhost 6.6.0-andromach #1 SMP PREEMPT aarch64 Toybox
```

See [docs/DESIGN.md](docs/DESIGN.md) for how it works and [docs/ROADMAP.md](docs/ROADMAP.md) for
what comes next: processes, Binder, properties, `init`, ART, graphics, then the iOS app in
two editions.

## Build and run (Mac, Apple Silicon)

```sh
brew install erofs-utils e2fsprogs llvm

# 1. Android's files, from the SDK's emulator image (sdkmanager "system-images;android-37.0;google_apis_playstore;arm64-v8a")
IMG=~/Library/Android/sdk/system-images/android-37.0/google_apis_playstore/arm64-v8a
python3 tools/extract_image.py $IMG/system.img work/parts
for p in system system_ext vendor product; do
    mkdir -p work/fs/$p && fsck.erofs --extract=work/fs/$p --no-preserve work/parts/$p.img
done
tools/extract_apex.sh work/fs/system work/fs/apex

# 2. The precompiled root (all of it, or --only <guest path> ... for a subset)
python3 tools/build_rootfs.py work/fs build/root

# 3. The runtime, and a program
make
build/amrun -r build/root /system/bin/sh
```

`amrun -s` traces system calls. `--deny-exec` refuses executable memory that does not come from
an image, which is the restriction the iOS app runs under.

## Layout

- `tools/amc.py` - the precompiler: one ELF file in, one signable Mach-O image out
- `tools/build_rootfs.py` - the whole guest root, with images in place of ELF files
- `tools/extract_image.py`, `tools/extract_apex.sh` - unpack the SDK system image
- `runtime/` - the Linux system-call layer on Darwin, and `amrun`

## License

MIT for andromach itself. The Android system image it builds from is Google's, under its own
licenses. It is not part of this repository and is not redistributed by it.
