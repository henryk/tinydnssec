#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include "ndelay.h"
#include "socket.h"
#include "haveip6.h"
#include "error.h"

#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT EINVAL
#endif
#ifndef EPFNOSUPPORT
#define EPFNOSUPPORT EAFNOSUPPORT
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT EAFNOSUPPORT
#endif

int socket_tcp6(void)
{
#ifdef LIBC_HAS_IP6
  int s;

  if (noipv6) goto compat;
  s = socket(PF_INET6,SOCK_STREAM,0);
  if (s == -1) {
    if (errno == EINVAL || errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT || errno == EPFNOSUPPORT) {
compat:
      s=socket(AF_INET,SOCK_STREAM,0);
      noipv6=1;
      if (s==-1) return -1;
    } else
    return -1;
  }
  if (ndelay_on(s) == -1) { close(s); return -1; }
#ifdef IPV6_V6ONLY
  {
    int zero=0;
    setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,(void*)&zero,sizeof(zero));
  }
#endif
  return s;
#else
  return socket_tcp();
#endif
}

