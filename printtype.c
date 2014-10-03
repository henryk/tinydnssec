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

#include "byte.h"
#include "dns.h"
#include "uint16.h"
#include "printtype.h"

int printtype(stralloc *out, const char type[2]) {
uint16 u16;

  if (byte_equal(type,2,DNS_T_A)) return stralloc_cats(out,"A");
  if (byte_equal(type,2,DNS_T_NS)) return stralloc_cats(out,"NS");
  if (byte_equal(type,2,DNS_T_CNAME)) return stralloc_cats(out,"CNAME");
  if (byte_equal(type,2,DNS_T_SOA)) return stralloc_cats(out,"SOA");
  if (byte_equal(type,2,DNS_T_PTR)) return stralloc_cats(out,"PTR");
  if (byte_equal(type,2,DNS_T_HINFO)) return stralloc_cats(out,"HINFO");
  if (byte_equal(type,2,DNS_T_MX)) return stralloc_cats(out,"MX");
  if (byte_equal(type,2,DNS_T_TXT)) return stralloc_cats(out,"TXT");
  if (byte_equal(type,2,DNS_T_RP)) return stralloc_cats(out,"RP");
  if (byte_equal(type,2,DNS_T_SIG)) return stralloc_cats(out,"SIG");
  if (byte_equal(type,2,DNS_T_KEY)) return stralloc_cats(out,"KEY");
  if (byte_equal(type,2,DNS_T_AAAA)) return stralloc_cats(out,"AAAA");
  if (byte_equal(type,2,DNS_T_OPT)) return stralloc_cats(out,"OPT");
  if (byte_equal(type,2,DNS_T_DS)) return stralloc_cats(out,"DS");
  if (byte_equal(type,2,DNS_T_RRSIG)) return stralloc_cats(out,"RRSIG");
  if (byte_equal(type,2,DNS_T_DNSKEY)) return stralloc_cats(out,"DNSKEY");
  if (byte_equal(type,2,DNS_T_NSEC3)) return stralloc_cats(out,"NSEC3");
  if (byte_equal(type,2,DNS_T_NSEC3PARAM)) return stralloc_cats(out,"NSEC3PARAM");
  if (byte_equal(type,2,DNS_T_AXFR)) return stralloc_cats(out,"AXFR");
  if (byte_equal(type,2,DNS_T_ANY)) return stralloc_cats(out,"*");

  uint16_unpack_big(type,&u16);
  return stralloc_catulong0(out,u16,0);
}
