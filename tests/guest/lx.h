// Minimal bionic declarations for guest tests: there is no NDK on the build machine.
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef int int32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef long off_t;
struct iovec { void *iov_base; size_t iov_len; };
struct msghdr { void *msg_name; uint32_t msg_namelen; struct iovec *msg_iov; size_t msg_iovlen; void *msg_control; size_t msg_controllen; int msg_flags; };
struct cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; };
#define CMSG_ALIGN(n) (((n) + 7) & ~7ul)
#define CMSG_DATA(c) ((unsigned char *)(c) + sizeof(struct cmsghdr))
#define CMSG_LEN(n) (sizeof(struct cmsghdr) + (n))
#define CMSG_SPACE(n) (sizeof(struct cmsghdr) + CMSG_ALIGN(n))
struct sockaddr { uint16_t sa_family; char sa_data[14]; };
struct sockaddr_un { uint16_t sun_family; char sun_path[108]; };
struct sockaddr_in { uint16_t sin_family; uint16_t sin_port; uint32_t sin_addr; char zero[8]; };
struct ucred { int pid; uint32_t uid, gid; };
struct timespec { long tv_sec, tv_nsec; };
struct itimerspec { struct timespec it_interval, it_value; };
struct epoll_event { uint32_t events; uint64_t data; };
struct pollfd { int fd; short events, revents; };
typedef struct { unsigned long fds_bits[16]; } fd_set;
struct timeval { long tv_sec, tv_usec; };
typedef unsigned long pthread_t;
#define AF_UNIX 1
#define AF_INET 2
#define AF_NETLINK 16
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_SEQPACKET 5
#define SOCK_NONBLOCK 04000
#define SOCK_CLOEXEC 02000000
#define SOL_SOCKET 1
#define SO_PASSCRED 16
#define SO_PEERCRED 17
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_REUSEADDR 2
#define SCM_RIGHTS 1
#define SCM_CREDENTIALS 2
#define MSG_PEEK 2
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT 0x40
#define MSG_NOSIGNAL 0x4000
#define MSG_CMSG_CLOEXEC 0x40000000
#define EPOLLIN 1
#define EPOLLOUT 4
#define EPOLLERR 8
#define EPOLLHUP 0x10
#define EPOLLRDHUP 0x2000
#define EPOLLONESHOT (1u<<30)
#define EPOLLET (1u<<31)
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
#define O_NONBLOCK 04000
#define O_RDWR 2
#define O_CREAT 0100
#define F_GETFL 3
#define F_SETFL 4
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define CLOCK_MONOTONIC 1
#define CLOCK_REALTIME 0
#define CLOCK_BOOTTIME 7
#define TFD_TIMER_ABSTIME 1
#define EFD_SEMAPHORE 1
#define EFD_NONBLOCK 04000
#define POLLIN 1
#define POLLOUT 4
#define POLLHUP 0x10
#define EAGAIN 11
#define ECONNREFUSED 111
#define EADDRINUSE 98
#define ENOENT 2
#define EPIPE 32
#define SHUT_WR 1
int *__errno(void);
#define errno (*__errno())
int printf(const char *, ...);
int snprintf(char *, size_t, const char *, ...);
int dprintf(int, const char *, ...);
void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
int strcmp(const char *, const char *);
char *strcpy(char *, const char *);
char *strerror(int);
void exit(int);
void *malloc(size_t);
void free(void *);
int socket(int, int, int);
int socketpair(int, int, int, int *);
int bind(int, const void *, uint32_t);
int listen(int, int);
int accept(int, void *, uint32_t *);
int accept4(int, void *, uint32_t *, int);
int connect(int, const void *, uint32_t);
int getsockname(int, void *, uint32_t *);
int getpeername(int, void *, uint32_t *);
int getsockopt(int, int, int, void *, uint32_t *);
int setsockopt(int, int, int, const void *, uint32_t);
ssize_t send(int, const void *, size_t, int);
ssize_t recv(int, void *, size_t, int);
ssize_t sendto(int, const void *, size_t, int, const void *, uint32_t);
ssize_t recvfrom(int, void *, size_t, int, void *, uint32_t *);
ssize_t sendmsg(int, const struct msghdr *, int);
ssize_t recvmsg(int, struct msghdr *, int);
int shutdown(int, int);
ssize_t read(int, void *, size_t);
ssize_t write(int, const void *, size_t);
ssize_t writev(int, const struct iovec *, int);
ssize_t readv(int, const struct iovec *, int);
int close(int);
int pipe(int *);
int unlink(const char *);
int mkdir(const char *, int);
int fcntl(int, int, ...);
int getpid(void);
int usleep(unsigned);
int epoll_create1(int);
int epoll_ctl(int, int, int, struct epoll_event *);
int epoll_wait(int, struct epoll_event *, int, int);
int eventfd(unsigned, int);
int timerfd_create(int, int);
int timerfd_settime(int, int, const struct itimerspec *, struct itimerspec *);
int timerfd_gettime(int, struct itimerspec *);
int clock_gettime(int, struct timespec *);
int memfd_create(const char *, unsigned);
int ftruncate(int, off_t);
void *mmap(void *, size_t, int, int, int, off_t);
int munmap(void *, size_t);
int signalfd(int, const void *, int);
int inotify_init1(int);
int inotify_add_watch(int, const char *, uint32_t);
int poll(struct pollfd *, unsigned long, int);
int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int pthread_create(pthread_t *, const void *, void *(*)(void *), void *);
int pthread_join(pthread_t, void **);
uint16_t htons(uint16_t);
uint32_t htonl(uint32_t);
struct ifaddrs;
int getifaddrs(struct ifaddrs **);
void freeifaddrs(struct ifaddrs *);
unsigned if_nametoindex(const char *);
