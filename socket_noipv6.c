#include "haveip6.h"

#ifdef LIBC_HAS_IP6
int noipv6=0;
#else
int noipv6=1;
#endif
