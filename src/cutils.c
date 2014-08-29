#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <linux/un.h>

#include "include/vpu_log.h"

#define ANDROID_SOCKET_ENV_PREFIX	"ANDROID_SOCKET_"
#define ANDROID_SOCKET_DIR		"/dev/socket"

#define ANDROID_RESERVED_SOCKET_PREFIX	"/dev/socket/"
#define FILESYSTEM_SOCKET_PREFIX	"/tmp/"

// Linux "abstract" (non-filesystem) namespace
#define ANDROID_SOCKET_NAMESPACE_ABSTRACT	0
// Android "reserved" (/dev/socket) namespace
#define ANDROID_SOCKET_NAMESPACE_RESERVED	1
// Normal filesystem namespace
#define ANDROID_SOCKET_NAMESPACE_FILESYSTEM	2

#define offsetof(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)

int ion_open()
{
    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0)
        VPM_ERROR("open /dev/ion failed!\n");
    return fd;
}

int ion_close(int fd)
{
    return close(fd);
}

static int ion_ioctl(int fd, int req, void *arg)
{
    int ret = ioctl(fd, req, arg);
    if (ret < 0) {
        VPM_ERROR("ioctl %x failed with code %d: %s\n", req,
           ret, strerror(errno));
        return -errno;
    }
    return ret;
}

/* Documented in header file. */
int socket_make_sockaddr_un(const char *name, int namespaceId, 
        struct sockaddr_un *p_addr, socklen_t *alen)
{
    memset (p_addr, 0, sizeof (*p_addr));
    size_t namelen;

    switch (namespaceId) {
        case ANDROID_SOCKET_NAMESPACE_ABSTRACT:
#ifdef HAVE_LINUX_LOCAL_SOCKET_NAMESPACE
            namelen  = strlen(name);

            // Test with length +1 for the *initial* '\0'.
            if ((namelen + 1) > sizeof(p_addr->sun_path)) {
                goto error;
            }

            /*
             * Note: The path in this case is *not* supposed to be
             * '\0'-terminated. ("man 7 unix" for the gory details.)
             */
            
            p_addr->sun_path[0] = 0;
            memcpy(p_addr->sun_path + 1, name, namelen);
#else /*HAVE_LINUX_LOCAL_SOCKET_NAMESPACE*/
            /* this OS doesn't have the Linux abstract namespace */

            namelen = strlen(name) + strlen(FILESYSTEM_SOCKET_PREFIX);
            /* unix_path_max appears to be missing on linux */
            if (namelen > (sizeof(*p_addr) - offsetof(struct sockaddr_un, sun_path) - 1)) {
                goto error;
            }

            strcpy(p_addr->sun_path, FILESYSTEM_SOCKET_PREFIX);
            strcat(p_addr->sun_path, name);
#endif /*HAVE_LINUX_LOCAL_SOCKET_NAMESPACE*/
        break;

        case ANDROID_SOCKET_NAMESPACE_RESERVED:
            namelen = strlen(name) + strlen(ANDROID_RESERVED_SOCKET_PREFIX);
            /* unix_path_max appears to be missing on linux */
            if (namelen > sizeof(*p_addr) 
                    - offsetof(struct sockaddr_un, sun_path) - 1) {
                goto error;
            }

            strcpy(p_addr->sun_path, ANDROID_RESERVED_SOCKET_PREFIX);
            strcat(p_addr->sun_path, name);
        break;

        case ANDROID_SOCKET_NAMESPACE_FILESYSTEM:
            namelen = strlen(name);
            /* unix_path_max appears to be missing on linux */
            if (namelen > sizeof(*p_addr) 
                    - offsetof(struct sockaddr_un, sun_path) - 1) {
                goto error;
            }

            strcpy(p_addr->sun_path, name);
        break;
        default:
            // invalid namespace id
            return -1;
    }

    p_addr->sun_family = AF_LOCAL;
    *alen = namelen + offsetof(struct sockaddr_un, sun_path) + 1;
    return 0;
error:
    return -1;
}
/**
 * connect to peer named "name" on fd
 * returns same fd or -1 on error.
 * fd is not closed on error. that's your job.
 * 
 * Used by AndroidSocketImpl
 */
int socket_local_client_connect(int fd, const char *name, int namespaceId, 
        int type)
{
    struct sockaddr_un addr;
    socklen_t alen;
    size_t namelen;
    int err;

    err = socket_make_sockaddr_un(name, namespaceId, &addr, &alen);

    if (err < 0) {
        goto error;
    }

    if(connect(fd, (struct sockaddr *) &addr, alen) < 0) {
        goto error;
    }

    return fd;

error:
    return -1;
}

/** 
 * connect to peer named "name"
 * returns fd or -1 on error
 */
int socket_local_client(const char *name, int namespaceId, int type)
{
    int s;

    s = socket(AF_LOCAL, type, 0);
    if(s < 0) return -1;

    if ( 0 > socket_local_client_connect(s, name, namespaceId, type)) {
        close(s);
        return -1;
    }

    return s;
}

/*
 * android_get_control_socket - simple helper function to get the file
 * descriptor of our init-managed Unix domain socket. `name' is the name of the
 * socket, as given in init.rc. Returns -1 on error.
 *
 * This is inline and not in libcutils proper because we want to use this in
 * third-party daemons with minimal modification.
 */
int android_get_control_socket(const char *name)
{
	char key[64] = ANDROID_SOCKET_ENV_PREFIX;
	const char *val;
	int fd;

	/* build our environment variable, counting cycles like a wolf ... */
#if HAVE_STRLCPY
	strlcpy(key + sizeof(ANDROID_SOCKET_ENV_PREFIX) - 1,
		name,
		sizeof(key) - sizeof(ANDROID_SOCKET_ENV_PREFIX));
#else	/* for the host, which may lack the almightly strncpy ... */
	strncpy(key + sizeof(ANDROID_SOCKET_ENV_PREFIX) - 1,
		name,
		sizeof(key) - sizeof(ANDROID_SOCKET_ENV_PREFIX));
	key[sizeof(key)-1] = '\0';
#endif

	val = getenv(key);
	if (!val)
		return -1;

	errno = 0;
	fd = strtol(val, NULL, 10);
	if (errno)
		return -1;

	return fd;
}

long gettid()
{
	return syscall(SYS_gettid);
}

void __android_log_print(int flag, char *src, char *fmt, char *msg)
{
    fprintf(stderr, "%s", msg);
    fflush(stderr);
}

size_t strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	if (n!=0) {
			while (--n != 0) {
			if ((*d++ = *s++) == 0)
			break;
		}
	}

	if (n==0) {
		if (siz != 0)
			*d = '\0';
		while (*s++)
			;
	}

	return (s - src - 1);
}

int property_get(const char *key, char *value, const char *default_value)
{
    int len;
    //len = __system_property_get(key, value);
    //if(len > 0) {
    //    return len;
    //}
    if(default_value) {
        len = strlen(default_value);
        memcpy(value, default_value, len + 1);
    }
    return len;
}
