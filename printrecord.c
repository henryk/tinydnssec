#include "uint16.h"
#include "uint32.h"
#include "error.h"
#include "byte.h"
#include "dns.h"
#include "printrecord.h"
#include "ip6.h"
#include "base32hex.h"
#include "printtype.h"

static char *d;

static const char *HEX = "0123456789ABCDEF";

static int hexout(stralloc *out,const char *buf,unsigned int len,unsigned int pos,unsigned int n) {
  unsigned char c;
  int i;

  for (i = 0; i < n; i++) {
    pos = dns_packet_copy(buf,len,pos,&c,1); if (!pos) return 0;
    if (!stralloc_catb(out,&HEX[(c>>4)&0xf],1)) return 0;
    if (!stralloc_catb(out,&HEX[c&0xf],1)) return 0;
  }
  return pos;
}

unsigned int printrecord_cat(stralloc *out,const char *buf,unsigned int len,unsigned int pos,const char *q,const char qtype[2])
{
  const char *x;
  char misc[20];
  uint16 datalen;
  uint16 u16;
  uint32 u32;
  unsigned int newpos;
  int i;
  unsigned char ch;
  int rawlen;

  pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,misc,10); if (!pos) return 0;
  uint16_unpack_big(misc + 8,&datalen);
  newpos = pos + datalen;

  if (q) {
    if (!dns_domain_equal(d,q))
      return newpos;
    if (byte_diff(qtype,2,misc) && byte_diff(qtype,2,DNS_T_ANY))
      return newpos;
  }

  if (!dns_domain_todot_cat(out,d)) return 0;
  if (!stralloc_cats(out," ")) return 0;
  if (byte_diff(misc,2,DNS_T_OPT)) {
    uint32_unpack_big(misc + 4,&u32);
    if (!stralloc_catulong0(out,u32,0)) return 0;

    if (byte_diff(misc + 2,2,DNS_C_IN)) {
      if (!stralloc_cats(out," weird class\n")) return 0;
      return newpos;
    }
  } else {
    if (!stralloc_cats(out,"0")) return 0;
  }

  x = 0;
  rawlen = 0;
  if (byte_equal(misc,2,DNS_T_NS)) x = " NS ";
  if (byte_equal(misc,2,DNS_T_PTR)) x = " PTR ";
  if (byte_equal(misc,2,DNS_T_CNAME)) x = " CNAME ";
  if (x) {
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    if (!stralloc_cats(out,x)) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
  }
  else if (byte_equal(misc,2,DNS_T_MX)) {
    if (!stralloc_cats(out," MX ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,2); if (!pos) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    uint16_unpack_big(misc,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
  }
  else if (byte_equal(misc,2,DNS_T_SOA)) {
    if (!stralloc_cats(out," SOA ")) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    if (!dns_domain_todot_cat(out,d)) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,20); if (!pos) return 0;
    for (i = 0;i < 5;++i) {
      if (!stralloc_cats(out," ")) return 0;
      uint32_unpack_big(misc + 4 * i,&u32);
      if (!stralloc_catulong0(out,u32,0)) return 0;
    }
  }
  else if (byte_equal(misc,2,DNS_T_A)) {
    if (datalen != 4) { errno = error_proto; return 0; }
    if (!stralloc_cats(out," A ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,4); if (!pos) return 0;
    for (i = 0;i < 4;++i) {
      ch = misc[i];
      if (i) if (!stralloc_cats(out,".")) return 0;
      if (!stralloc_catulong0(out,ch,0)) return 0;
    }
  }
  else if (byte_equal(misc,2,DNS_T_AAAA)) {
    char ip6str[IP6_FMT];
    int stringlen;
    if (datalen != 16) { errno = error_proto; return 0; }
    if (!stralloc_cats(out," AAAA ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,16); if (!pos) return 0;
    stringlen=ip6_fmt(ip6str,misc);
    if (!stralloc_catb(out,ip6str,stringlen)) return 0;
  }
  else if (byte_equal(misc,2,DNS_T_DNSKEY)) {
    pos = dns_packet_copy(buf,len,pos,misc,4); if (!pos) return 0;
    if (!stralloc_cats(out," DNSKEY ")) return 0;
    uint16_unpack_big(misc,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catulong0(out,misc[2],0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catulong0(out,misc[3],0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    rawlen = datalen - 4;
  }
  else if (byte_equal(misc,2,DNS_T_DS)) {
    pos = dns_packet_copy(buf,len,pos,misc,4); if (!pos) return 0;
    if (!stralloc_cats(out," DS ")) return 0;
    uint16_unpack_big(misc,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catulong0(out,misc[2],0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catulong0(out,misc[3],0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    pos = hexout(out,buf,len,pos,datalen - 4); if (!pos) return 0;
  }
  else if (byte_equal(misc,2,DNS_T_RRSIG)) {
    pos = dns_packet_copy(buf,len,pos,misc,18); if (!pos) return 0;
    if (!stralloc_cats(out," RRSIG ")) return 0;
    if (!printtype(out,misc)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catulong0(out,misc[2],0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catulong0(out,misc[3],0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint32_unpack_big(misc + 4,&u32);
    if (!stralloc_catulong0(out,u32,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint32_unpack_big(misc + 8,&u32);
    if (!stralloc_catulong0(out,u32,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint32_unpack_big(misc + 12,&u32);
    if (!stralloc_catulong0(out,u32,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint16_unpack_big(misc + 16,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    rawlen = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    rawlen = datalen - 18 - (rawlen - pos);
    pos += datalen - 18 - rawlen;
    if (!dns_domain_todot_cat(out,d)) return 0;
    if (!stralloc_cats(out," ")) return 0;
  }
  else if (byte_equal(misc,2,DNS_T_NSEC3)) {
    char nextHash[255];
    char nextOwner[255*8/5];
    int j;
    pos = dns_packet_copy(buf,len,pos,misc,5); if (!pos) return 0;
    if (!stralloc_cats(out," NSEC3 ")) return 0;
    if (!stralloc_catulong0(out,misc[0],0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catulong0(out,misc[1],0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    uint16_unpack_big(misc+2,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!misc[4])
      if (!stralloc_cats(out,"-")) return 0;
    pos = hexout(out,buf,len,pos,misc[4]); if (!pos) return 0;
    if (!stralloc_cats(out," ")) return 0;
    pos = dns_packet_copy(buf,len,pos,misc,1); if (!pos) return 0;
    pos = dns_packet_copy(buf,len,pos,nextHash,misc[0]); if (!pos) return 0;
    i = base32hex(nextOwner, nextHash, misc[0]);
    if (!stralloc_catb(out,nextOwner,i)) return 0;
    while (pos < newpos) {
      pos = dns_packet_copy(buf,len,pos,misc,2); if (!pos) return 0;
      pos = dns_packet_copy(buf,len,pos,nextHash,misc[1]); if (!pos) return 0;
      j = 8 * misc[1];
      for (i = 0; i < j; i++) {
	if (nextHash[i/8] & (1 << (7 - (i%8)))) {
	  misc[1] = i;
	  if (!stralloc_cats(out," ")) return 0;
	  if (!printtype(out,misc)) return 0;
	}
      }
    }
  }
  else if (byte_equal(misc,2,DNS_T_OPT)) {
    if (!stralloc_cats(out," OPT ")) return 0;
    uint16_unpack_big(misc+2, &u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catulong0(out,misc[4],0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!stralloc_catulong0(out,misc[5],0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    if (!hexout(out,misc,8,6,2)) return 0;
    rawlen = datalen;
  }
  else {
    if (!stralloc_cats(out," ")) return 0;
    uint16_unpack_big(misc,&u16);
    if (!stralloc_catulong0(out,u16,0)) return 0;
    if (!stralloc_cats(out," ")) return 0;
    rawlen = datalen;
  }
    while (rawlen--) {
      pos = dns_packet_copy(buf,len,pos,misc,1); if (!pos) return 0;
      if ((misc[0] >= 33) && (misc[0] <= 126) && (misc[0] != '\\')) {
        if (!stralloc_catb(out,misc,1)) return 0;
      }
      else {
        ch = misc[0];
        misc[3] = '0' + (7 & ch); ch >>= 3;
        misc[2] = '0' + (7 & ch); ch >>= 3;
        misc[1] = '0' + (7 & ch);
        misc[0] = '\\';
        if (!stralloc_catb(out,misc,4)) return 0;
      }
    }

  if (!stralloc_cats(out,"\n")) return 0;
  if (pos != newpos) { errno = error_proto; return 0; }
  return newpos;
}

unsigned int printrecord(stralloc *out,const char *buf,unsigned int len,unsigned int pos,const char *q,const char qtype[2])
{
  if (!stralloc_copys(out,"")) return 0;
  return printrecord_cat(out,buf,len,pos,q,qtype);
}
