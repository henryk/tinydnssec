#include <unistd.h>
#include "uint16.h"
#include "open.h"
#include "tai.h"
#include "cdb.h"
#include "byte.h"
#include "case.h"
#include "dns.h"
#include "seek.h"
#include "response.h"
#include "ip6.h"
#include "clientloc.h"
#include "alloc.h"
#include "sha1.h"
#include "base32hex.h"

static int want(const char *owner,const char type[2])
{
  unsigned int pos;
  static char *d;
  char x[10];
  uint16 datalen;

  pos = dns_packet_skipname(response,response_len,12); if (!pos) return 0;
  pos += 4;

  while (pos < response_len) {
    pos = dns_packet_getname(response,response_len,pos,&d); if (!pos) return 0;
    pos = dns_packet_copy(response,response_len,pos,x,10); if (!pos) return 0;
    if (dns_domain_equal(d,owner))
      if (byte_equal(type,2,x))
        return 0;
    uint16_unpack_big(x + 8,&datalen);
    pos += datalen;
  }
  return 1;
}

static char *d1;
static char *wantAddr;
static char clientloc[2];
static struct tai now;
static struct cdb c;

static char data[32767];
static uint32 dlen;
static unsigned int dpos;
static char type[2];
static uint32 ttl;
static char *nsec3;
static char *cname = 0;

/* returns -1 on failure,
 * returns 0 on not found
 * returns 1 when found
 * returns 2 when flagwild is true and no wildcard match has been found but
 * a direct match exists. This is for RFC-1034 section 4.3.3 compatibility.
 */ 
static int find(char *d,int flagwild)
{
  int r, direct=0;
  char ch;
  struct tai cutoff;
  char ttd[8];
  char ttlstr[4];
  char recordloc[2];
  double newttl;

  for (;;) {
    r = cdb_findnext(&c,d,dns_domain_length(d));
    if (r < 0) return r; /* -1 */
    if (r == 0) { return flagwild ? direct ? 2 : 0
				  : 0; }
    dlen = cdb_datalen(&c);
    if (dlen > sizeof data) return -1;
    if (cdb_read(&c,data,dlen,cdb_datapos(&c)) == -1) return -1;
    dpos = dns_packet_copy(data,dlen,0,type,2); if (!dpos) return -1;
    dpos = dns_packet_copy(data,dlen,dpos,&ch,1); if (!dpos) return -1;
    if ((ch == '=' + 1) || (ch == '*' + 1) || (ch == '6' + 1)) {
      --ch;
      dpos = dns_packet_copy(data,dlen,dpos,recordloc,2); if (!dpos) return -1;
      if (byte_diff(recordloc,2,clientloc)) continue;
    }
    direct = direct || (ch != '*');
    if (flagwild != (ch == '*')) continue;
    dpos = dns_packet_copy(data,dlen,dpos,ttlstr,4); if (!dpos) return -1;
    uint32_unpack_big(ttlstr,&ttl);
    dpos = dns_packet_copy(data,dlen,dpos,ttd,8); if (!dpos) return -1;
    if (byte_diff(ttd,8,"\0\0\0\0\0\0\0\0")) {
      tai_unpack(ttd,&cutoff);
      if (ttl == 0) {
	if (tai_less(&cutoff,&now)) continue;
	tai_sub(&cutoff,&cutoff,&now);
	newttl = tai_approx(&cutoff);
	if (newttl <= 2.0) newttl = 2.0;
	if (newttl >= 3600.0) newttl = 3600.0;
	ttl = newttl;
      }
      else
	if (!tai_less(&cutoff,&now)) continue;
    }
    return 1;
  }
}

static int dobytes(unsigned int len)
{
  char buf[20];
  if (len > 20) return 0;
  dpos = dns_packet_copy(data,dlen,dpos,buf,len);
  if (!dpos) return 0;
  return response_addbytes(buf,len);
}

static int doname(void)
{
  dpos = dns_packet_getname(data,dlen,dpos,&d1);
  if (!dpos) return 0;
  return response_addname(d1);
}

static int addNSEC3(char *hashName)
{
int r;

  cdb_findstart(&c);
  while (r = find(hashName,0)) {
    if (r == -1) return 0;
    if (byte_equal(type,2,DNS_T_NSEC3)) {
      if (!response_rstart(hashName,DNS_T_NSEC3,ttl)) return 0;
      if (!response_addbytes(data + dpos,dlen - dpos)) return 0;
      response_rfinish(RESPONSE_AUTHORITY);
    }
    else if (do_dnssec && byte_equal(type,2,DNS_T_RRSIG) && dlen > dpos+18
	     && byte_equal(data+dpos,2,DNS_T_NSEC3)) {
      if (!response_rstart(hashName,DNS_T_RRSIG,ttl)) return 0;
      if (!dobytes(18)) return 0;
      if (!doname()) return 0;
      if (!response_addbytes(data + dpos,dlen - dpos)) return 0;
      response_rfinish(RESPONSE_AUTHORITY);
    }
  }
  return 1;
}

static int addNSEC3Cover(char *name, char *control, int wild)
{
SHA1_CTX ctx;
int algo = 0, flags = 0, saltlen = 0, r;
uint16 iterations = 0;
char salt[255];
uint8_t digest[SHA1_DIGEST_SIZE];

  /* Search NSEC3PARAM to find hash parameters */
  cdb_findstart(&c);
  while (r = find(control,0)) {
    if (r == -1) return 0;
    if (byte_equal(type,2,DNS_T_NSEC3PARAM) && dlen - dpos > 5) {
      algo = data[dpos];
      flags = data[dpos+1];
      uint16_unpack_big(data + dpos + 2, &iterations);
      saltlen = data[dpos+4];
      if (algo != 1 || flags || dlen - dpos - 5 < saltlen) {
	algo = 0;
      } else {
	byte_copy(salt,saltlen, data + dpos + 5);
	break;
      }
    }
  }
  if (algo != 1) return 0; /* not found or unsupported algorithm / flags */

  /* Compute hash value */
  case_lowerb(name,dns_domain_length(name));
  SHA1_Init(&ctx);
  if (wild) SHA1_Update(&ctx, "\1*", 2);
  SHA1_Update(&ctx, name, dns_domain_length(name));
  SHA1_Update(&ctx, salt, saltlen);
  SHA1_Final(&ctx, digest);
  while (iterations-- > 0) {
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, digest, SHA1_DIGEST_SIZE);
    SHA1_Update(&ctx, salt, saltlen);
    SHA1_Final(&ctx, digest);
  }

  /* Find covering hash */
  char nibble = ((digest[0] >> 4) & 0xf) + '0';
  if (nibble > '9') { nibble += 'a' - '9' - 1; }
  salt[0] = 1;
  salt[1] = nibble;
  byte_copy(salt+2, dns_domain_length(control), control);
  cdb_findstart(&c);
  while (r = find(salt,0)) {
    if (r == -1) return 0;
    if (byte_equal(type,2,DNS_T_HASHLIST) && dlen - dpos >= SHA1_DIGEST_SIZE) {
      int hpos = dpos + SHA1_DIGEST_SIZE;
      while (byte_diff(digest,SHA1_DIGEST_SIZE,data+hpos) > 0 && hpos < dlen) hpos += SHA1_DIGEST_SIZE;
      hpos -= SHA1_DIGEST_SIZE;
      *salt = base32hex(salt+1,data+hpos,SHA1_DIGEST_SIZE);
      byte_copy(salt + *salt + 1, dns_domain_length(control), control);
      break;
    }
  }
  if (*salt == 1) return 0; /* not found */
  return addNSEC3(salt);
}

static int addClosestEncloserProof(char *name, char *control, int includeWild)
{
char *q = name;
char *hashName = 0;
int r;

  while (*q) {
    cdb_findstart(&c);
    while (r = find(q,0)) {
      if (r == -1) return 0;
      if (byte_equal(type,2,DNS_T_HASHREF) && dlen > dpos) {
        if (!dns_packet_getname(data,dlen,dpos,&hashName)) return 0;
	break;
      }
    }
    if (hashName) {
      int rc = addNSEC3(hashName);
      alloc_free(hashName);
      if (!rc) return 0;
      hashName = 0;
      break;
    }
    name = q;
    q += *q + 1;
  }
  if (!*q) return 0;
  if (includeWild && !addNSEC3Cover(q, control, 1)) return 0;
  return addNSEC3Cover(name, control, 0);
}

static int doit(char *q,char qtype[2])
{
  unsigned int bpos;
  unsigned int anpos;
  unsigned int aupos;
  unsigned int arpos;
  char *control;
  char *wild;
  int flaggavesoa;
  int flagfound;
  int r;
  int flagns;
  int flagauthoritative;
  int flagsigned;
  char *flagcname;
  char x[20];
  uint16 u16;
  char addr[8][4];
  char addr6[8][16];
  int addrnum,addr6num;
  uint32 addrttl,addr6ttl;
  int i;

  anpos = response_len;

  control = q;
  for (;;) {
    flagns = 0;
    flagauthoritative = 0;
    flagsigned = 0;
    cdb_findstart(&c);
    while (r = find(control,0)) {
      if (r == -1) return 0;
      if (byte_equal(type,2,DNS_T_SOA)) flagauthoritative = 1;
      else if (byte_equal(type,2,DNS_T_NS)) flagns = 1;
      else if (byte_equal(type,2,DNS_T_DNSKEY)) flagsigned |= 1;
      else if (byte_equal(type,2,DNS_T_RRSIG)) flagsigned |= 2;
      else if (byte_equal(type,2,DNS_T_NSEC3PARAM)) flagsigned |= 4;
    }
    flagsigned = (flagsigned == 7);
    if (flagns) break;
    if (!*control) {
      if (!cname) return 0; /* q is not within our bailiwick */
      response[2] &= ~4; /* CNAME chain ends in external reference */
      return 1;
    }
    control += *control;
    control += 1;
  }

  wild = q;
  if (!flagauthoritative) {
    response[2] &= ~4;
    goto AUTHORITY; /* q is in a child zone */
  }


  flaggavesoa = 0;
  flagfound = 0;
  flagcname = 0;
  if (nsec3) {
    alloc_free(nsec3);
    nsec3 = 0;
  }

  for (;;) {
    addrnum = addr6num = 0;
    addrttl = addr6ttl = 0;
    cdb_findstart(&c);
    while (r = find(wild,wild != q)) {
      if (r == -1) return 0;
      if (r == 2) break;
      flagfound = 1;
      if (flaggavesoa && byte_equal(type,2,DNS_T_SOA)) continue;
      if (do_dnssec && byte_equal(type,2,DNS_T_HASHREF) && dlen > dpos) {
        if (!dns_packet_getname(data,dlen,dpos,&nsec3)) return 0;
      }
      if (byte_diff(type,2,qtype) && byte_diff(qtype,2,DNS_T_ANY) && byte_diff(type,2,DNS_T_CNAME)
	  && (!do_dnssec || byte_diff(type,2,DNS_T_RRSIG))) continue;
      if (byte_equal(type,2,DNS_T_HASHREF) || byte_equal(type,2,DNS_T_HASHLIST)) continue;
      if (do_dnssec && byte_equal(type,2,DNS_T_RRSIG) && dlen - dpos > 18) {
	char sigtype[2];
	struct tai valid;
	uint32 validFrom, validUntil;
	byte_copy(sigtype,2,data + dpos);
	if (byte_diff(sigtype,2,qtype) && byte_diff(qtype,2,DNS_T_ANY) && byte_diff(sigtype,2,DNS_T_CNAME)) continue;
	uint32_unpack_big(data + dpos + 12, &validFrom);
	tai_unix(&valid, validFrom);
	if (tai_less(&now, &valid)) continue;
	uint32_unpack_big(data + dpos + 8, &validUntil);
	tai_unix(&valid, validUntil);
	if (tai_less(&valid, &now)) continue;
      }
      if (byte_equal(type,2,DNS_T_A) && (dlen - dpos == 4) && (!do_dnssec || addrnum < 8)) {
	addrttl = ttl;
	i = dns_random(addrnum + 1);
	if (i < 8) {
	  if ((i < addrnum) && (addrnum < 8))
	    byte_copy(addr[addrnum],4,addr[i]);
	  byte_copy(addr[i],4,data + dpos);
	}
	if (addrnum < 1000000) ++addrnum;
	continue;
      }
      if (byte_equal(type,2,DNS_T_AAAA) && (dlen - dpos == 16) && (!do_dnssec || addr6num < 8)) {
	addr6ttl = ttl;
	i = dns_random(addr6num + 1);
	if (i < 8) {
	  if ((i < addr6num) && (addr6num < 8))
	    byte_copy(addr6[addr6num],16,addr6[i]);
	  byte_copy(addr6[i],16,data + dpos);
	}
	if (addr6num < 1000000) ++addr6num;
	continue;
      }
      if (!response_rstart(q,type,ttl)) return 0;
      if (byte_equal(type,2,DNS_T_NS) || byte_equal(type,2,DNS_T_CNAME) || byte_equal(type,2,DNS_T_PTR)) {
	if (!doname()) return 0;
	if (byte_equal(type,2,DNS_T_CNAME) && byte_diff(qtype,2,DNS_T_CNAME)) {
	  if (!dns_domain_copy(&flagcname,d1)) return 0;
	}
      }
      else if (byte_equal(type,2,DNS_T_MX)) {
	if (!dobytes(2)) return 0;
	if (!doname()) return 0;
      }
      else if (byte_equal(type,2,DNS_T_SOA)) {
	if (!doname()) return 0;
	if (!doname()) return 0;
	if (!dobytes(20)) return 0;
        flaggavesoa = 1;
      }
      else if (byte_equal(type,2,DNS_T_RRSIG) && dlen - dpos > 18) {
	char sigtype[2];
	byte_copy(sigtype,2,data + dpos);
	if (!dobytes(18)) return 0;
	if (!doname()) return 0;
        if (!response_addbytes(data + dpos,dlen - dpos)) return 0;
      }
      else
        if (!response_addbytes(data + dpos,dlen - dpos)) return 0;
      response_rfinish(RESPONSE_ANSWER);
    }
    if (r == 2) break;
    for (i = 0;i < addrnum;++i)
      if (i < 8) {
	if (!response_rstart(q,DNS_T_A,addrttl)) return 0;
	if (!response_addbytes(addr[i],4)) return 0;
	response_rfinish(RESPONSE_ANSWER);
      }
    for (i = 0;i < addr6num;++i)
      if (i < 8) {
	if (!response_rstart(q,DNS_T_AAAA,addr6ttl)) return 0;
	if (!response_addbytes(addr6[i],16)) return 0;
	response_rfinish(RESPONSE_ANSWER);
      }

    if (flagfound) break;
    if (wild == control) break;
    if (!*wild) break; /* impossible */
    wild += *wild;
    wild += 1;
  }

  if (flagcname) {
    if (response[RESPONSE_ANSWER+1] >= 100) {
      dns_domain_free(&flagcname); /* most likely a loop */
      return 0;
    }
    if (cname) dns_domain_free(&cname);
    cname = flagcname;
    return doit(cname, qtype);
  }

  if (!flagfound)
    response_nxdomain();


  AUTHORITY:
  aupos = response_len;

  if (flagauthoritative && (aupos == anpos)) { /* NODATA or NXDOMAIN */
    if (!flaggavesoa) {
      cdb_findstart(&c);
      while (r = find(control,0)) {
	if (r == -1) return 0;
	if (!flaggavesoa && byte_equal(type,2,DNS_T_SOA)) {
	  if (!response_rstart(control,DNS_T_SOA,ttl)) return 0;
	  if (!doname()) return 0;
	  if (!doname()) return 0;
	  if (!dobytes(20)) return 0;
	  response_rfinish(RESPONSE_AUTHORITY);
          flaggavesoa = 1;
	}
	else if (do_dnssec && byte_equal(type,2,DNS_T_RRSIG) && dlen > dpos+18
		 && byte_equal(data+dpos,2,DNS_T_SOA)) {
          if (!response_rstart(control,DNS_T_RRSIG,ttl)) return 0;
	  if (!dobytes(18)) return 0;
	  if (!doname()) return 0;
          if (!response_addbytes(data + dpos,dlen - dpos)) return 0;
          response_rfinish(RESPONSE_AUTHORITY);
	}
      }
    }
    if (do_dnssec && flagsigned) {
      if (flagfound && nsec3) { /* NODATA */
	if (!addNSEC3(nsec3)) return 0;
	if (wild != q) { /* Wildcard NODATA */
	  if (!addClosestEncloserProof(q, control, 0)) return 0;
	}
      }
      else { /* NXDOMAIN, or query for NSEC3 owner name */
	if (!addClosestEncloserProof(q, control, 1)) return 0;
      }
    }
  }
  else {
    if (do_dnssec && wild != q && flagsigned) { /* Wildcard answer */
      char *nextCloser = q;
      while (nextCloser + *nextCloser + 1 < wild) { nextCloser += *nextCloser + 1; }
      if (!addNSEC3Cover(nextCloser, control, 0)) return 0;
    }
    if (want(control,DNS_T_NS)) {
      int have_ds = 0;
      cdb_findstart(&c);
      while (r = find(control,0)) {
        if (r == -1) return 0;
        if (byte_equal(type,2,DNS_T_NS)) {
          if (!response_rstart(control,DNS_T_NS,ttl)) return 0;
	  if (!doname()) return 0;
          response_rfinish(RESPONSE_AUTHORITY);
        }
        else if (do_dnssec && byte_equal(type,2,DNS_T_DS)) {
          if (!response_rstart(control,DNS_T_DS,ttl)) return 0;
          if (!response_addbytes(data + dpos,dlen - dpos)) return 0;
          response_rfinish(RESPONSE_AUTHORITY);
	  have_ds = 1;
        }
	else if (do_dnssec && byte_equal(type,2,DNS_T_RRSIG) && dlen > dpos+18
		 && (byte_equal(data+dpos,2,DNS_T_NS)
		     || byte_equal(data+dpos,2,DNS_T_DS))) {
          if (!response_rstart(control,DNS_T_RRSIG,ttl)) return 0;
	  if (!dobytes(18)) return 0;
	  if (!doname()) return 0;
          if (!response_addbytes(data + dpos,dlen - dpos)) return 0;
          response_rfinish(RESPONSE_AUTHORITY);
	}
      }
      if (do_dnssec && !flagauthoritative && !have_ds) { addNSEC3(control); }
    }
  }

  arpos = response_len;
  if (do_dnssec) {
    /* Add EDNS0 OPT RR */
    if (!response_rstart("",DNS_T_OPT,1 << 15)) return 0;
    uint16_pack_big(response+arpos+3, 512);
    response_rfinish(RESPONSE_ADDITIONAL);
  }

  bpos = anpos;
  while (bpos < arpos) {
    bpos = dns_packet_skipname(response,arpos,bpos); if (!bpos) return 0;
    bpos = dns_packet_copy(response,arpos,bpos,x,10); if (!bpos) return 0;
    if (byte_equal(x,2,DNS_T_NS) || byte_equal(x,2,DNS_T_MX)) {
      if (byte_equal(x,2,DNS_T_NS)) {
        if (!dns_packet_getname(response,arpos,bpos,&wantAddr)) return 0;
      }
      else
        if (!dns_packet_getname(response,arpos,bpos + 2,&wantAddr)) return 0;
      case_lowerb(wantAddr,dns_domain_length(wantAddr));
      if (want(wantAddr,DNS_T_A)) {
	cdb_findstart(&c);
	while (r = find(wantAddr,0)) {
          if (r == -1) return 0;
	  if (byte_equal(type,2,DNS_T_A)) {
            if (!response_rstart(wantAddr,DNS_T_A,ttl)) return 0;
	    if (!dobytes(4)) return 0;
            response_rfinish(RESPONSE_ADDITIONAL);
	  }
	  else if (byte_equal(type,2,DNS_T_AAAA)) {
            if (!response_rstart(wantAddr,DNS_T_AAAA,ttl)) return 0;
	    if (!dobytes(16)) return 0;
            response_rfinish(RESPONSE_ADDITIONAL);
	  }
	  else if (do_dnssec && byte_equal(type,2,DNS_T_RRSIG) && dlen > dpos+18
		   && (byte_equal(data+dpos,2,DNS_T_A) || byte_equal(data+dpos,2,DNS_T_AAAA))) {
            if (!response_rstart(wantAddr,DNS_T_RRSIG,ttl)) return 0;
	    if (!dobytes(18)) return 0;
	    if (!doname()) return 0;
            if (!response_addbytes(data + dpos,dlen - dpos)) return 0;
            response_rfinish(RESPONSE_ADDITIONAL);
	  }
        }
      }
    }
    uint16_unpack_big(x + 8,&u16);
    bpos += u16;
  }

  if (flagauthoritative && (response_len > max_response_len)) {
    byte_zero(response + RESPONSE_ADDITIONAL,2);
    response_len = arpos;
    if (!do_dnssec && response_len > max_response_len) {
      byte_zero(response + RESPONSE_AUTHORITY,2);
      response_len = aupos;
    }
  }

  return 1;
}

int respond(char *q,char qtype[2],char ip[16])
{
  int fd;
  int r;

  find_client_loc(clientloc, ip);

  tai_now(&now);
  fd = open_read("data.cdb");
  if (fd == -1) return 0;
  cdb_init(&c,fd);

  r = doit(q,qtype);
  if (cname) {
    dns_domain_free(&cname);
  }

  cdb_free(&c);
  close(fd);
  return r;
}
