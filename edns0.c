/* (C) 2012 Peter Conrad <conrad@quisquis.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dns.h"
#include "edns0.h"
#include "response.h"
#include "uint16.h"

unsigned int check_edns0(const char header[12], const char *buf, const int len, unsigned int pos)
{
char opt_class[2];
char opt_ttl[4];

  max_response_len = 512;
  do_dnssec = 0;
  if (!header[6] && !header[7] && !header[8] && !header[9]
	&& !header[10] && header[11] == 1) {
    char nametype[3];
    uint16 size, min_len;
    pos = dns_packet_copy(buf,len,pos,nametype,3); if (!pos) return pos;
    if (nametype[0] || nametype[1] || nametype[2] != DNS_T_OPT[1]) return pos;
    pos = dns_packet_copy(buf,len,pos,opt_class,2); if (!pos) return pos;
    pos = dns_packet_copy(buf,len,pos,opt_ttl,4); if (!pos) return pos;
    if (opt_ttl[0]) return pos; // unsupported RCODE in query
    if (opt_ttl[1]) return pos; // unsupported version
    do_dnssec = opt_ttl[2] & 0x80;
    uint16_unpack_big(opt_class, &size);
    min_len = do_dnssec ? 1220 : 512;
    max_response_len = size > 4000 ? 4000 : size;
    if (max_response_len < min_len) { max_response_len = min_len; }
  }
  return pos;
}
