#include "open.h"
#include "byte.h"
#include "cdb.h"
#include "ip6.h"

int find_client_loc(char loc[2],const char ip[16])
{
  int r, fd;
  char key[32+3];
  static struct cdb c;

  fd = open_read("data.cdb");
  if (fd == -1) return 0;
  cdb_init(&c,fd);

  byte_zero(loc,2);
  key[0] = 0;
  key[1] = '%';
  if (byte_equal(ip,12,V4mappedprefix)) {
    key[2] = 'f';
    byte_copy(key + 3,4,ip+12);
    r = cdb_find(&c,key,7);
    if (!r) r = cdb_find(&c,key,6);
    if (!r) r = cdb_find(&c,key,5);
    if (!r) r = cdb_find(&c,key,4);
    if (!r) r = cdb_find(&c,key,3);
    if (r == -1) return 0;
    if (r && (cdb_datalen(&c) == 2))
      if (cdb_read(&c,loc,2,cdb_datapos(&c)) == -1) return 0;
  } else {
    unsigned int n;
    key[2] = 's';
    ip6_fmt_flat(key+3,ip);
    for (n=19; n>3; --n) {
      r = cdb_find(&c,key,n);
      if (r) break;
    }
    if (r == -1) return 0;
    if (r && (cdb_datalen(&c) == 2))
      if (cdb_read(&c,loc,2,cdb_datapos(&c)) == -1) return 0;
  }

  cdb_free(&c);
  close(fd);
  return r;
}
