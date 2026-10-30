// Event files: epoll, eventfd, timerfd, signalfd, memfd, inotify. Not implemented yet.
#include "am.h"
#include "linux.h"

long sys_event(am_ctx *c, long nr, bool *handled) {
    *handled = false;
    return 0;
}
