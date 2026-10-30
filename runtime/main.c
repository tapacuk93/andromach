// amrun: run one Android program from a precompiled root on the Mac. The development harness
// for the runtime that the iOS app embeds.
//
//   amrun -r <root> [-d <datadir>] [-s] [--deny-exec] [--] <guest path> [args...]
#include "am.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__thread am_thread *am_self;
const char *am_root;
const char *am_datadir;
int am_strace;
bool am_deny_exec;

static void usage(void) {
    fprintf(stderr, "usage: amrun -r <root> [-d <datadir>] [-s] [--deny-exec] [--] <guest path> [args...]\n");
    exit(2);
}

int main(int argc, char **argv) {
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc) am_root = argv[++i];
        else if (!strcmp(argv[i], "-d") && i + 1 < argc) am_datadir = argv[++i];
        else if (!strcmp(argv[i], "-s")) am_strace = 1;
        else if (!strcmp(argv[i], "--deny-exec")) am_deny_exec = true;
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else usage();
    }
    if (!am_root || i >= argc) usage();
    if (!am_datadir) {
        static char d[1024];
        snprintf(d, sizeof d, "%s/.andromach-data", getenv("HOME"));
        am_datadir = d;
    }
    if (getenv("AM_STRACE")) am_strace = 1;

    am_proc *proc = am_proc_new(NULL);
    am_init_pid = proc->pid;
    am_self = am_thread_new(proc, proc->pid);
    am_self->host = pthread_self();
    am_trap_init();
    am_signal_init();
    am_binder_init();
    am_fs_register_devices();
    am_thread_tsd_init(0);

    char *envp[] = {
        "PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin",
        "ANDROID_ROOT=/system", "ANDROID_DATA=/data", "ANDROID_STORAGE=/storage",
        "ANDROID_ART_ROOT=/apex/com.android.art", "ANDROID_I18N_ROOT=/apex/com.android.i18n",
        "ANDROID_TZDATA_ROOT=/apex/com.android.tzdata", "ANDROID_ASSETS=/system/app",
        "HOME=/data/local/tmp", "TMPDIR=/data/local/tmp", "TERM=xterm-256color", "SHELL=/system/bin/sh",
        "BOOTCLASSPATH=", NULL,
    };
    static am_ctx c;
    long r = am_exec(&c, argv[i], argv + i, envp);
    if (r < 0) {
        fprintf(stderr, "amrun: cannot start %s: error %ld\n", argv[i], -r);
        return 127;
    }
    am_resume(&c);
}
