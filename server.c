#include "edns0.h"
#include "byte.h"
#include "case.h"
#include "env.h"
#include "buffer.h"
#include "strerr.h"
#include "ip4.h"
#include "ip6.h"
#include "uint16.h"
#include "ndelay.h"
#include "socket.h"
#include "droproot.h"
#include "qlog.h"
#include "response.h"
#include "dns.h"
#include "alloc.h"
#include "iopause.h"
#include "str.h"

extern char *fatal;
extern char *starting;
extern int respond(char *,char *,char *);
extern void initialize(void);

static char ip[16];
static uint16 port;

static char buf[513];
static int len;

static char *q;

void nomem()
{
  strerr_die2x(111,fatal,"out of memory");
}

static int doit(void)
{
  unsigned int pos;
  char header[12];
  char qtype[2];
  char qclass[2];

  if (len >= sizeof buf) goto NOQ;
  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) goto NOQ;
  if (header[2] & 128) goto NOQ;
  if (header[4]) goto NOQ;
  if (header[5] != 1) goto NOQ;

  pos = dns_packet_getname(buf,len,pos,&q); if (!pos) goto NOQ;
  pos = dns_packet_copy(buf,len,pos,qtype,2); if (!pos) goto NOQ;
  pos = dns_packet_copy(buf,len,pos,qclass,2); if (!pos) goto NOQ;

  if (!response_query(q,qtype,qclass)) goto NOQ;
  response_id(header);
  if (byte_equal(qclass,2,DNS_C_IN))
    response[2] |= 4;
  else
    if (byte_diff(qclass,2,DNS_C_ANY)) goto WEIRDCLASS;
  response[3] &= ~128;
  if (!(header[2] & 1)) response[2] &= ~1;

  if (header[2] & 126) goto NOTIMP;
  if (byte_equal(qtype,2,DNS_T_AXFR)) goto NOTIMP;

  pos = check_edns0(header, buf, len, pos);
  if (!pos) goto NOQ;

  case_lowerb(q,dns_domain_length(q));
  if (!respond(q,qtype,ip)) {
    qlog(ip,port,header,q,qtype," - ");
    return 0;
  }
  qlog(ip,port,header,q,qtype," + ");
  return 1;

  NOTIMP:
  response[3] &= ~15;
  response[3] |= 4;
  qlog(ip,port,header,q,qtype," I ");
  return 1;

  WEIRDCLASS:
  response[3] &= ~15;
  response[3] |= 1;
  qlog(ip,port,header,q,qtype," C ");
  return 1;

  NOQ:
  qlog(ip,port,"\0\0","","\0\0"," / ");
  return 0;
}

int main()
{
  char *x;
  int *udp53;
  unsigned int off;
  unsigned int cnt;
  iopause_fd *iop;

  x = env_get("IP");
  if (!x)
    strerr_die2x(111,fatal,"$IP not set");
  off=cnt=0;
  while (x[off]) {
    unsigned int l;
    char dummy[16];
    l=ip6_scan(x+off,dummy);
    if (!l)
      strerr_die3x(111,fatal,"unable to parse IP address ",x+off);
    cnt++;
    if (!x[off+l]) break;
    if (x[off+l]=='%')
      while (x[off+l] && x[off+l]!=',') ++l;
    if (x[off+l]!=',')
      strerr_die3x(111,fatal,"unable to parse IP address ",x+off);
    off+=l+1;
  }
  udp53=(int *) alloc(sizeof(int) *cnt);
  if (!udp53) nomem();
  iop=(iopause_fd *) alloc(sizeof(*iop) * cnt);
  if (!iop) nomem();

  off=cnt=0;
  while (x[off]) {
    unsigned int l;
    uint32 ifid=0;
    l=ip6_scan(x+off,ip);
    udp53[cnt] = socket_udp6();
    if (udp53[cnt] == -1)
      strerr_die2sys(111,fatal,"unable to create UDP socket: ");
    if (x[off+l]=='%') {
      char* interface=x+off+l+1;
      int Len=str_chr(interface,',');
      if (interface[Len]) {
	interface[Len]=0;
	ifid=socket_getifidx(interface);
	interface[Len]=',';
      } else
	ifid=socket_getifidx(interface);
      l+=Len;
    }
    if (socket_bind6_reuse(udp53[cnt],ip,53,ifid) == -1)
      strerr_die2sys(111,fatal,"unable to bind UDP socket: ");
    ndelay_off(udp53[cnt]);
    socket_tryreservein(udp53[cnt],65536);
    iop[cnt].fd=udp53[cnt];
    iop[cnt].events=IOPAUSE_READ;
    cnt++;
    if (!x[off+l]) break;
    off+=l+1;
  }
  droproot(fatal);

  initialize();

  buffer_putsflush(buffer_2,starting);

  for (;;) {
    struct taia stamp;
    struct taia deadline;
    unsigned int i;
    uint32 ifid;
    taia_now(&stamp);
    taia_uint(&deadline,300);
    taia_add(&deadline,&deadline,&stamp);
    iopause(iop,cnt,&deadline,&stamp);
    for (i=0;i<cnt;i++)
      if (iop[i].revents) {
	len = socket_recv6(udp53[i],buf,sizeof buf,ip,&port,&ifid);
	if (len < 0) continue;
	if (!doit()) continue;
	if (response_len > max_response_len) response_tc();
	socket_send6(udp53[i],response,response_len,ip,port,ifid);
	/* may block for buffer space; if it fails, too bad */
      }
  }
}
