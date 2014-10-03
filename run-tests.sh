#!/bin/sh

# (C) 2012 Peter Conrad <conrad@quisquis.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

./tinydns-sign.pl test/example.?sk <test/data >data
./tinydns-data

for i in test/q-*; do
    id="${i#test/q}"
    echo -n "$i ... "
    read sec type name <"$i"
    ./tinydns-get "$sec" "$type" $name | tail -n +2 >test/"o$id"
    sed -s 's/\b[0-9]\{10\}\b/<TIME>/g;/00 RRSIG /s/[^ ]*$/<SIG>/;s/^[0-9]\{1,\}/<SIZE>/' <test/"o$id" >test/"t$id"
    if diff "test/t$id" "test/a$id" >/dev/null; then
	echo "OK"
    else
	echo "FAIL: tinydns-get"
    fi
done

function dig2tiny {
    awk 'BEGIN { sect = 0; }
	 /^;; QUESTION SECTION/ { sect = 1; }
	 /^;; ANSWER SECTION/ { sect = 2; }
	 /^;; AUTHORITY SECTION/ { sect = 3; }
	 /^;; ADDITIONAL SECTION/ { sect = 4; }
	 /^;; OPT PSEUDOSECTION/ { sect = 5; }
	 /^;; ->>HEADER<<./ { sect = 6; }
	 { if ($0 !~ /^;;/ && $0 !~ /^$/) {
	     if (sect == 1) { print "query: " $3 " " substr($1, 2) }
	     else if (sect == 2) { print "answer: " $0 }
	     else if (sect == 3) { print "authority: " $0 }
	     else if (sect == 4) { print "additional: " $0 }
	     else if (sect == 5) { print "additional: . 0 OPT " $8 " " (0 + $4) " 0 " ($6 == "do;" ? "8000" : "0") }
	   } else if (sect == 6) {
	     if ($0 ~ /^;; ...HEADER/ && $5 == "status:") { status = substr($6, 0, length($6) -1); }
	     else if ($0 ~ /^;; flags: /) {
		if ($0 ~ /^;; flags: [ a-z]*aa/) { auth = "authoritative, " }
		else { auth = "" }
		match($0, /QUERY: ([[:digit:]]+), ANSWER: ([[:digit:]]+), AUTHORITY: ([[:digit:]]+), ADDITIONAL: ([[:digit:]]+)/, rrs);
		print "<SIZE> bytes, " rrs[1] "+" rrs[2] "+" rrs[3] "+" rrs[4] " records, response, " auth status;
	     }
	   }
	 }' <"$1" | \
      sed 's=[ 	]\{1,\}= =g;s=\(example\|xx\)\. =\1 =g;s=\(example\|xx\)\.$=\1=;s= IN = =g;s=\([0-9a-zA-Z+/]\{40,\}\) =\1=g' >"$2"
}

if [ "$1" = "-t" ]; then
    shift
    for i in test/q-*; do
	id="${i#test/q}"
	echo -n "$i (tcp) ... "
	read sec type name <"$i"
	if [ "$sec" = "-s" ]; then
	    sec="+dnssec +bufsize=1220"
	elif [ "$sec" = "-S" ]; then
	    sec="+dnssec +bufsize=2000"
	fi
	dig +norecurse +tcp $sec "$type" $name @$SERVER >"test/ot$id"
	dig2tiny "test/ot$id" "test/ttt$id"
	sed -s 's/\b[0-9]\{10\}\b/<TIME>/g;s/\b[0-9]\{14\}\b/<TIME>/g;/00 RRSIG /s/[^ ]*$/<SIG>/' <test/"ttt$id" | \
	  sort >test/"tt$id"
	if sort <"test/a$id" | diff -i - "test/tt$id" >/dev/null; then
	    echo "OK"
	else
	    echo "FAIL: dig +tcp"
	fi
    done
fi

if [ "$1" = "-u" ]; then
    shift
    for i in test/q-*; do
	id="${i#test/q}"
	echo -n "$i (udp) ... "
	read sec type name <"$i"
	if [ "$sec" = "-s" ]; then
	    sec="+dnssec +bufsize=1220"
	elif [ "$sec" = "-S" ]; then
	    sec="+dnssec +bufsize=2000"
	fi
	dig +norecurse +notcp $sec "$type" $name @$SERVER >"test/ou$id"
	dig2tiny "test/ou$id" "test/tut$id"
	sed -s 's/\b[0-9]\{10\}\b/<TIME>/g;s/\b[0-9]\{14\}\b/<TIME>/g;/00 RRSIG /s/[^ ]*$/<SIG>/' <test/"tut$id" | \
	  sort >test/"tu$id"
	if sort <"test/a$id" | diff -i - "test/tu$id" >/dev/null; then
	    echo "OK"
	else
	    echo "FAIL: dig +notcp"
	fi
    done
fi
