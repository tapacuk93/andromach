# Roadmap

Each step ends with something that runs.

1. **Native programs** - done: `linker64`, bionic, `toybox`, `mksh` from signed images on macOS.
2. **Processes** - `fork`/`vfork` + `execve` as new guests in the one address space; `wait4`,
   process groups, signal delivery (`rt_sigaction` handlers, `rt_sigreturn`, `tgkill`, faults
   into guest handlers: ART uses SIGSEGV for null checks and stack overflow).
3. **Kernel interfaces Android needs** - AF_UNIX sockets with fd passing, epoll, eventfd,
   timerfd, signalfd, memfd/ashmem, inotify, netlink basics, a `/proc` and `/sys` subset,
   `/dev/__properties__`.
4. **Binder** - `/dev/binder`, `/dev/hwbinder` and `/dev/vndbinder` as a driver inside the
   runtime: transactions, object references, death notifications, fd passing.
5. **Boot** - `init` with its own `.rc` files: `linkerconfig`, `servicemanager`, `logd`, the
   property service, `apexd` (APEXes are already unpacked, so it runs in a pass-through mode).
6. **ART** - `app_process` / zygote replacement, the boot image precompiled, JIT off;
   `system_server` up.
7. **Graphics** - the gfxstream host side over Metal; SurfaceFlinger and HWComposer to a
   CAMetalLayer; input from UIKit touches.
8. **The iOS app** - the runtime as a framework, the root as signed images in the bundle, `/data`
   in the app container; Lite and Full editions from per-edition app lists.
9. **Snapshots** - start from a saved, already booted state rather than booting each launch.
