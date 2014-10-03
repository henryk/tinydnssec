#include "buffer.h"
#include "exit.h"
#include "strerr.h"
#include "ip6.h"
#include "dns.h"

#define FATAL "dnsipq: fatal: "

static char seed[128];

static stralloc in;
static stralloc fqdn;
static stralloc out;
char str[IP6_FMT];

int main(int argc,char **argv)
{
  int i;

  dns_random_init(seed);

  if (*argv) ++argv;

  while (*argv) {
    if (!stralloc_copys(&in,*argv))
      strerr_die2x(111,FATAL,"out of memory");
    if (dns_ip6_qualify(&out,&fqdn,&in) == -1)
      strerr_die4sys(111,FATAL,"unable to find IP6 address for ",*argv,": ");

    buffer_put(buffer_1,fqdn.s,fqdn.len);
    buffer_puts(buffer_1," ");
    for (i = 0;i + 16 <= out.len;i += 16) {
      buffer_put(buffer_1,str,ip6_fmt(str,out.s + i));
      buffer_puts(buffer_1," ");
    }
    buffer_puts(buffer_1,"\n");

    ++argv;
  }

  buffer_flush(buffer_1);
  _exit(0);
}
