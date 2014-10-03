#include <sys/types.h>
#include <sys/stat.h>
#include "str.h"
#include "ip4.h"
#include "ip6.h"
#include "byte.h"
#include "okclient.h"

static char fn[3 + IP6_FMT];

int okclient(char ip[16])
{
  struct stat st;
  int i;
  char sep;

  fn[0] = 'i';
  fn[1] = 'p';
  fn[2] = '/';
  if (byte_equal(ip,12,V4mappedprefix)) {
    fn[3 + ip4_fmt(fn + 3,ip+12)] = 0;
    sep='.';
  } else {
    fn[3 + ip6_fmt(fn + 3,ip)] = 0;
    sep=':';
  }

  for (;;) {
    if (!fn[3]) return 0;
    if (stat(fn,&st) == 0) return 1;
    /* treat temporary error as rejection */
    i = str_rchr(fn,sep);
    if (!fn[i]) return 0;
    fn[i] = 0;
  }
}
