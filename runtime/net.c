// Sockets: AF_UNIX (stream, dgram, seqpacket; filesystem and abstract names; SCM_RIGHTS,
// SCM_CREDENTIALS) and AF_INET/AF_INET6 over the host's sockets. Not implemented yet.
#include "am.h"
#include "linux.h"

long sys_net(am_ctx *c, long nr, bool *handled) {
    *handled = false;
    return 0;
}
