#!/usr/bin/perl -w

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

use strict;
use Fcntl;
use Digest::SHA1 qw(sha1 sha1_hex);
use Crypt::OpenSSL::RSA;
use MIME::Base64;

$main::ttl = 432000;
%main::keys = ();
%main::names = ();
@main::zones = ();
%main::locs = ();
$main::catchAllLoc = undef;

while ($#ARGV >= 0) {
    if ($ARGV[0] eq '-h' || $ARGV[0] eq '--help') {
	&usage();
	# usage does not return
    } elsif ($ARGV[0] eq '-t') {
	if ($#ARGV < 1) { &usage(); }
	$main::ttl = $ARGV[1];
	shift @ARGV;
    } elsif ($ARGV[0] eq '-g') {
	if ($#ARGV != 5) { &usage(); }
	&genkey($ARGV[1], $ARGV[2], $ARGV[3], $ARGV[4], $ARGV[5]);
	# genkey does not return
	exit(0);
    } else { # keyfile
	&addKey($ARGV[0]);
    }
    shift @ARGV;
}

my $now = time();
while ($_ = <STDIN>) {
    s/\s+$//s;
    if (/^:[^:]*:(43|46|48|50|51|6528[12]):/) { next; }
    if (/^$/ || /^-/ || /^#[^KDP]/) {
	print "$_\n";
	next;
    }
    if (/^\./) {
	print "# Was: $_\n";
	while (! /^\.([^:]*):([0-9.]*):([^:]+):(\d*):(\d*):([^:]*)$/) { $_ .= ':'; }
	my ($dom,$ip,$ns,$ttl,$ts,$lo) = /^\.([^:]*):([0-9.]*):([^:]+):(\d*):(\d*):([^:]*)$/;
	#  &fqdn:ip:x:ttl:timestamp:lo
	print "\&$dom:$ip:$ns:$ttl:$ts:$lo\n";
	$dom =~ tr/A-Z/a-z/;
	$ns =~ tr/A-Z/a-z/;
	if ($ns !~ /\./) { $ns .= ".ns.$dom"; }
	my $rec = &getOrCreateRRs($dom);
	$rec->addNS($ns, $ttl, $ts, $lo);
	&addA($ns, $ip, $ttl || 259200, $ts, $lo);
	if (exists($rec->{byType}->{6})) { next; } # don't create more than one SOA per zone
	# Zfqdn:mname:rname:ser:ref:ret:exp:min:ttl:timestamp:lo
	$_ = "Z$dom:$ns:hostmaster.${dom}:::::$ttl:$ts:$lo\n";
    }
    if (/^Z/) {
	my @fields = split /:/;
	if ($#fields < 3 || $fields[3] !~ /^00/) {
	    $fields[3] = $now;
	    $_ = join(":", @fields);
	}
    }
    print "$_\n";
    if (/^%(\w\w?):?/) {
	$main::locs{$1} = $';
	if ($' eq "") {
	    $main::catchAllLoc = $1;
	}
    } elsif (/^#[KDP]/) {
	if (/^#K([^:]*):(\d+):(\d*):(\d+):([^:]*):(\d*):(\d*):([^:]*)$/) {
	    # C<#Kname:flags:proto:algorithm:key:ttl:timestamp:lo>
	    my ($dom,$flags,$proto,$alg,$key,$ttl,$ts,$lo) = ($1, $2, $3, $4, $5, $6, $7, $8);
	    $dom =~ tr/A-Z/a-z/;
	    my $pubkey = decode_base64($key);
	    my $rdata = &htons($flags).chr($proto).chr($alg).$pubkey;
	    &makeGenericRecord($dom, 48, $rdata, $ttl, $ts, $lo);
	    my $rrs = &getOrCreateRRs($dom);
	    $rrs->addKey($flags, $alg, $pubkey);
	    $rrs->addRecord(48, $rdata, $ttl, $ts, $lo);
	} elsif (/^#D([^:]*):(\d+):(\d+):(\d+):([0-9a-fA-F]*):(\d*):(\d*):([^:]*)$/) {
	    # C<#Dname:tag:algorithm:digest:fingerprint:ttl:timestamp:lo>
	    my ($dom,$tag,$alg,$dig,$fp,$ttl,$ts,$lo) = ($1, $2, $3, $4, $5, $6, $7, $8);
	    $dom =~ tr/A-Z/a-z/;
	    my $rdata = &htons($tag).chr($alg).chr($dig).pack("H*", $fp);
	    &makeGenericRecord($dom, 43, $rdata, $ttl, $ts, $lo);
	    &getOrCreateRRs($dom)->addRecord(43, $rdata, $ttl, $ts, $lo);
	} elsif (/^#P([^:]*):(\d+):(\d+):(\d+):(\d*):([0-9a-fA-F]*):(\d*):(\d*):([^:]*)$/) {
	    # C<#Pname:algorithm:flags:iter:len:salt:ttl:timestamp:lo>
	    my ($dom,$alg,$flag,$iter,$len,$salt,$ttl,$ts,$lo) = ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	    $dom =~ tr/A-Z/a-z/;
	    if ($salt eq "") {
		if ($len eq "") { $len = 4; }
		open(RANDOM, "</dev/urandom") or die("Failed to open /dev/urandom");
		sysread(RANDOM, $salt, $len);
		close(RANDOM);
		$salt = unpack("H*", $salt);
	    } else {
		$len = length(pack("H*", $salt));
	    }
	    my $rdata = chr($alg).chr($flag).&htons($iter)
			.chr($len).pack("H*", $salt);
	    &makeGenericRecord($dom, 51, $rdata, $ttl, $ts, $lo);
	    my $rrs = &getOrCreateRRs($dom);
	    $rrs->addNS3P($alg, $flag, $iter, $salt, $ttl, $ts, $lo);
	    $rrs->addRecord(51, $rdata, $ttl, $ts, $lo);
	} else {
	    print STDERR "Warning: ignored incomplete pseudo record '$_'!\n";
	}
	next;
    }
    my $type = substr($_, 0, 1);
    if ($type !~ /^[.\&=+\@'^CZ:36]/) {
	print STDERR "Warning: ignored unknown record type '$type'\n";
	next;
    }
    my @stuff = split(/:/, substr($_, 1));
    if ($#stuff < 0) {
	print STDERR "Warning: ignored empty record '$_'\n";
	next;
    }
    my $dom = shift @stuff;
    $dom =~ tr/A-Z/a-z/;
    my $rec = &getOrCreateRRs($dom);
    if ($type eq '&') {
	# &fqdn:ip:x:ttl:timestamp:lo
	my $ns = $stuff[1];
	if ($ns !~ /\./) { $ns .= ".ns.$dom"; }
	$rec->addNS($ns, $stuff[2], $stuff[3], $stuff[4]);
	&addA($ns, $stuff[0], $stuff[2] || 259200, $stuff[3], $stuff[4]);
    } elsif ($type eq '=') {
	# =fqdn:ip:ttl:timestamp:lo
	$rec->addA($stuff[0], $stuff[1], $stuff[2], $stuff[3]);
	&addPTR($stuff[0], $dom, $stuff[1], $stuff[2], $stuff[3]);
    } elsif ($type eq '+') {
	# +fqdn:ip:ttl:timestamp:lo
	$rec->addA($stuff[0], $stuff[1], $stuff[2], $stuff[3]);
    } elsif ($type eq '6') {
	# =fqdn:ip6:ttl:timestamp:lo
	$rec->addAAAA($stuff[0], $stuff[1], $stuff[2], $stuff[3]);
	&addPTR($stuff[0], $dom, $stuff[1], $stuff[2], $stuff[3]);
    } elsif ($type eq '3') {
	# +fqdn:ip6:ttl:timestamp:lo
	$rec->addAAAA($stuff[0], $stuff[1], $stuff[2], $stuff[3]);
    } elsif ($type eq '@') {
	# @fqdn:ip:x:dist:ttl:timestamp:lo
	my $mx = $stuff[1];
	if ($mx !~ /\./) { $mx .= ".mx.$dom"; }
	$rec->addMX($mx, $stuff[2], $stuff[3], $stuff[4], $stuff[5]);
	&addA($mx, $stuff[0], $stuff[3], $stuff[4], $stuff[5]);
    } elsif ($type eq "'") {
	# 'fqdn:s:ttl:timestamp:lo
	$rec->addTXT(&parseData($stuff[0]), $stuff[1], $stuff[2], $stuff[3]);
    } elsif ($type eq '^') {
	# ^fqdn:p:ttl:timestamp:lo
	$rec->addPTR($stuff[0], $stuff[1], $stuff[2], $stuff[3]);
    } elsif ($type eq 'C') {
	# Cfqdn:p:ttl:timestamp:lo
	$rec->addCNAME($stuff[0], $stuff[1], $stuff[2], $stuff[3]);
    } elsif ($type eq 'Z') {
	# Zfqdn:mname:rname:ser:ref:ret:exp:min:ttl:timestamp:lo
	$rec->addSOA($stuff[0], $stuff[1], $stuff[2], $stuff[3], $stuff[4], $stuff[5], $stuff[6], $stuff[7], $stuff[8], $stuff[9]);
    } elsif ($type eq ':') {
	# :fqdn:n:rdata:ttl:timestamp:lo
	$rec->addRecord($stuff[0], &parseData($stuff[1]), $stuff[2], $stuff[3], $stuff[4]);
    }
}

foreach my $rec (values %main::names) {
    my $dom = $rec->{name};
    if (exists($rec->{byType}->{48})) {
	if (!exists($rec->{byType}->{6})) {
	    print STDERR "Warning: useless DNSKEY for $dom without SOA!\n";
	} elsif (!exists($rec->{byType}->{51})) {
	    print STDERR "ERROR: DNSKEY for $dom without NSEC3PARAM!\n";
	    exit(1);
	}
    } elsif (exists($rec->{byType}->{51})) {
	print STDERR "Warning: useless NSEC3PARAM for $dom without DNSKEY!\n";
    }
    &findControl($rec);
}

foreach my $zone (@main::zones) {
    my $rec = $main::names{$zone};
    if (!exists($rec->{keys})) {
	print STDERR "Info: ignore unsigned zone $zone\n";
	foreach my $dom (keys %{$rec->{zone}}) {
	    delete $main::names{$dom};
	}
	next;
    }
    if (!exists($rec->{nsec3p})) {
	next;
    }

    #
    # Add NSEC3 RRs to zone
    my %hashes = ();
    my $n3p = $rec->{nsec3p}->[0];
    # Generate hashes
    foreach my $name (keys %{$rec->{zone}}) {
	my $rr;
	LOOP: { do {
	    $rr = &getOrCreateRRs($name);
	    if (exists($rr->{hash})) { last; }
	    $rec->{zone}->{$name} = $rr;
	    my $hash = &nsec3hash($name, $n3p->{iterations}, $n3p->{salt});
	    if (exists($hashes{$hash})) {
		print STDERR "ERROR: hash collision on $name!?\n";
		exit(1);
	    }
	    $hashes{$hash} = { hash => $hash, name => &base32hex($hash).".".$zone,
			       generator => $name, zone => $zone };
	    $rr->{hash} = $hash;
	    if ($name eq $zone) { last; }
	    if ($name =~ /^[^.]*\./) { $name = $'; }
	} while ($rr->{name} ne $zone); }
    }
    # Find next hash in hash sort order
    my ($first, $prev);
    my @byNibble = ();
    my $prevNib = -1;
    foreach my $hash (sort keys %hashes) {
	my $nib = ord($hash) >> 4;
	if (!defined($byNibble[$nib])) {
	    while ($prevNib < $nib) {
		$byNibble[++$prevNib] = defined($prev) ? [$prev->{hash}] : [];
	    }
	}
	push @{$byNibble[$nib]}, $hash;
	if (!$first) {
	    $first = $prev = $hashes{$hash};
	    next;
	}
	$prev->{next} = $hash;
	$prev = $hashes{$hash};
    }
    $prev->{next} = $first->{hash};
    unshift @{$byNibble[0]}, $prev->{hash};
    for (my $nib = 1; $#{$byNibble[$nib]} < 0; $nib++) {
	unshift @{$byNibble[$nib]}, $prev->{hash};
    }
    for (my $nib = $#byNibble + 1; $nib < 16; $nib++) {
	$byNibble[$nib] = [$prev->{hash}];
    }
    # Generate records
    foreach my $hash (values %hashes) {
	my $rRec = &getOrCreateRRs($hash->{name});
	my $gRec = &getOrCreateRRs($hash->{generator});
	$rec->{zone}->{$hash->{name}} = $rRec;
	my $rdata = chr($n3p->{alg}).chr($n3p->{flags})
		    .&htons($n3p->{iterations})
		    .chr(length($n3p->{salt})).$n3p->{salt}
		    .chr(length($hash->{next})).$hash->{next}
		    .&genTypeBitmaps(keys %{$gRec->{byType}});
	print "# NSEC3: ".$hash->{name}." - ".&base32hex($hash->{next})." ("
	      .join(" ", sort keys %{$gRec->{byType}}).")\n";
	$rRec->addRecord(50, $rdata, $n3p->{ttl}, $n3p->{ts}, $n3p->{lo});
	&makeGenericRecord($hash->{name}, 50, $rdata, $n3p->{ttl}, $n3p->{ts}, $n3p->{lo});
	print "# H(".$hash->{generator}.") -> ".$hash->{name}."\n";
	#$gRec->addRecord(65281, &wireName($hash->{name}), $n3p->{ttl}, $n3p->{ts}, $n3p->{lo});
	&makeGenericRecord($hash->{generator}, 65281, &wireName($hash->{name}), $n3p->{ttl}, $n3p->{ts}, $n3p->{lo});
    }
    for (my $nib = 0; $nib < 16; $nib++) {
	my $name = sprintf("%x", $nib).".$zone";
	my $rec = &getOrCreateRRs($name);
	$rec->addRecord(65282, join("", @{$byNibble[$nib]}), $n3p->{ttl}, $n3p->{ts}, $n3p->{lo});
	&makeGenericRecord($name, 65282, join("", @{$byNibble[$nib]}), $n3p->{ttl}, $n3p->{ts}, $n3p->{lo});
    }

    # Add RRSIGs to zone
    my (@zsks, @ksks);
    if (!$rec->{haveSEP} || !$rec->{haveZSK}) {
	@zsks = @ksks = @{$rec->{keys}};
    } else {
	@ksks = grep {   $_->{flags} & 1  } @{$rec->{keys}};
	@zsks = grep { !($_->{flags} & 1) } @{$rec->{keys}};
    }
    my $validFrom = $now - 3600;
    my $validUntil = $now + $main::ttl;
    foreach my $owner (values %{$rec->{zone}}) {
	my $name = $owner->{name};
	my $isCutpoint = exists($owner->{byType}->{2}) && $name ne $zone;
	foreach my $type (keys %{$owner->{byType}}) {
	    if ($isCutpoint && $type != 43 && $type != 50) { next; }
	    my $labels = $name;
	    $labels =~ s/^\*\.//;
	    $labels =~ s/[^.]+//g;
	    $labels = length($labels) + 1;
	    my $ttl = $owner->{byType}->{$type}->[0]->{ttl} || 86400;
	    foreach my $key ($type == 48 ? @ksks : @zsks) {
		my $keytag = $key->{key}->{basetag} + $key->{alg} + $key->{flags};
		$keytag = ($keytag + ($keytag >> 16)) & 0xffff;
		my $rdata = &htons($type).chr($key->{alg}).chr($labels)
			   .&htonl($ttl).&htonl($validUntil)
			   .&htonl($validFrom)
			   .&htons($keytag).&wireName($zone);
		my $toSign = $rdata;
		foreach my $rr (sort { $a->{rdata} cmp $b->{rdata} } @{$owner->{byType}->{$type}}) {
		    $toSign .= &wireName($name).&htons($type)."\0\1".&htonl($ttl)
			      .&htons(length($rr->{rdata})).$rr->{rdata};
		}
		$key->{key}->{key}->use_pkcs1_padding();
		if ($key->{alg} == 7) {
		    $key->{key}->{key}->use_sha1_hash();
		} elsif ($key->{alg} == 8) {
		    $key->{key}->{key}->use_sha256_hash();
		} elsif ($key->{alg} == 10) {
		    $key->{key}->{key}->use_sha512_hash();
		} else {
		    print STDERR "Unsupported key type ".$key->{alg}."\n";
		    exit 1;
		}
		my $sig = $key->{key}->{key}->sign($toSign);
		if (!$sig || !$key->{key}->{key}->verify($toSign, $sig)) {
		    print STDERR "Failed to sign $name ($type)!?\n";
		    exit 1;
		}
		#$key->{key}->{key}->use_no_padding();
		#print "# ".unpack("H*", $key->{key}->{key}->public_decrypt($sig))."\n";
		$rdata .= $sig;
		print "# RRSIG $type ".$key->{alg}." $labels $ttl $validUntil $validFrom "
		      ."$keytag $name\n";
		&makeGenericRecord($name, 46, $rdata, $ttl, "", "");
	    }
	}
    }
}

exit(0);

package Records;

sub new {
    my ($class, $dom) = @_;
    $dom =~ tr/A-Z/a-z/;
    my $self = { name => $dom, byType => {}, haveSEP => 0, haveZSK => 0,
		 locs => {}, zone => {} };
    $self->{zone}->{$dom} = $self;
    bless $self, $class;
    return $self;
}

sub addKey {
my ($self, $flags, $alg, $key) = @_;

    if (!($flags & 0x100)) { return; }
    if (!exists($main::keys{$key})) {
	print STDERR "ERROR: encountered DNSKEY pseudo record without a matching key:\n";
	print STDERR "$_\n";
	exit 1;
    }
    if ($alg != 7 && $alg != 8 && $alg != 10) {
	print STDERR "Warning: ignoring DNSKEY with unsupported algorithm $alg\n";
	return;
    }
    my $entry = { flags => $flags, alg => $alg, pubkey => $key,
		  key => $main::keys{$key} };
    if (exists($self->{keys})) {
	foreach my $other (@{$self->{keys}}) {
	    if ($other->{flags} == $flags && $other->{alg} == $alg
		    && $other->{pubkey} eq $key) {
		return;
	    }
	}
	push @{$self->{keys}}, $entry;
    } else {
	$self->{keys} = [$entry];
    }
    if ($flags & 1) {
	$self->{haveSEP} = 1;
    } else {
	$self->{haveZSK} = 1;
    }
}

sub addNS3P {
my ($self, $alg, $flag, $iter, $salt, $ttl, $ts, $lo) = @_;

    if ($flag ne "0") {
	print STDERR "Warning: don't know about NSEC3 flags values != 0, ignoring\n";
    }
    if ($iter > 150) {
	print STDERR "Warning: large iteration count $iter may lead to problems\n";
    }
    if ($alg ne "1") {
	print STDERR "ERROR: NSEC3 algorithm $alg unknown. Please use algorithm 1.\n";
	exit 1;
    }

    my $entry = { flags => $flag, alg => $alg, iterations => $iter,
		  salt => pack("H*", $salt), ttl => $ttl, ts => $ts, lo => $lo };
    if (exists($self->{nsec3p})) {
	print STDERR "Warning: ignoring additional NSEC3PARAM for ".$self->{name}."\n";
#	foreach my $other (@$self->{nsec3p}) {
#	    if ($other->{flags} == $flag && $other->{alg} == $alg
#		    && $other->{iterations} == $iter
#		    && $other->{salt} eq $entry->{salt}) {
#		return;
#	    }
#	}
#	push @$self->{nsec3p}, $entry;
    } else {
	$self->{nsec3p} = [$entry];
    }
}

sub addRecord {
my ($self, $type, $data, $ttl, $ts, $lo) = @_;

    if (!defined($lo)) { $lo = ""; }
    if (!defined($ttl) || $ttl eq "") { $ttl = 86400; }
    $self->{locs}->{$lo} = 1;
    my $entry = { type => $type, rdata => $data, ttl => $ttl, ts => $ts, lo => $lo };
    if (!exists($self->{byType}->{$type})) {
	$self->{byType}->{$type} = [$entry];
	return;
    }
    foreach my $other (@{$self->{byType}->{$type}}) {
	if ($other->{rdata} eq $data
		&& ($other->{lo} eq $lo || $lo eq "" || $other->{lo} eq "")
		&& (($other->{ttl} eq "0") != ($ttl eq "0"))) {
	    print STDERR "Warning: duplicate record ".$self->{name}.":$type:...\n";
	    return;
	}
	if (($other->{lo} eq $lo || $lo eq "" || $other->{lo} eq "")
		&& (($other->{ttl} eq "0") == ($ttl eq "0"))
		&& $other->{ttl} ne $ttl) {
	    print STDERR "Warning: ttl mismatch for ".$self->{name}.":$type:...\n";
	    return;
	}
    }
    push @{$self->{byType}->{$type}}, $entry;
}

sub addA {
my ($self, $ip, $ttl, $ts, $lo) = @_;

    if ($ip !~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
	print STDERR "Warning: ignoring unparsable IPv4 address '$ip'\n";
	return;
    }
    $self->addRecord(1, pack("C*", $1, $2, $3, $4), $ttl, $ts, $lo);
}

sub addNS {
my ($self, $ns, $ttl, $ts, $lo) = @_;

    $self->addRecord(2, &toDomain($ns), $ttl || 259200, $ts, $lo);
}

sub addCNAME {
my ($self, $nm, $ttl, $ts, $lo) = @_;

    $self->addRecord(5, &toDomain($nm), $ttl, $ts, $lo);
}

sub addSOA {
my ($self, $ns, $hm, $ser, $ref, $ret, $exp, $min, $ttl, $ts, $lo) = @_;

    $self->addRecord(6, &toDomain($ns).&toDomain($hm)
			.pack("N*", $ser || 1, $ref || 16384, $ret || 2048,
				    $exp || 1048576, $min || 2560),
		     $ttl || 2560, $ts, $lo);
}

sub addPTR {
my ($self, $nm, $ttl, $ts, $lo) = @_;

    $self->addRecord(12, &toDomain($nm), $ttl, $ts, $lo);
}

sub addMX {
my ($self, $mx, $dist, $ttl, $ts, $lo) = @_;

    $self->addRecord(15, pack("n", $dist || 0).&toDomain($mx), $ttl, $ts, $lo);
}

sub addTXT {
my ($self, $txt, $ttl, $ts, $lo) = @_;

    my $cstr = "";
    while ((my $l = length($txt)) > 0) {
	if ($l > 255) { $l = 255; }
	$cstr .= chr($l).substr($txt, 0, $l);
	$txt = substr($txt, $l);
    }
    $self->addRecord(16, $cstr, $ttl, $ts, $lo);
}

sub addAAAA {
my ($self, $ip, $ttl, $ts, $lo) = @_;

    if ($ip !~ /^[0-9a-f]{32}$/i) {
	print STDERR "Warning: ignoring unparsable IPv6 address '$ip'\n";
	return;
    }
    $self->addRecord(28, pack("H*", $ip), $ttl, $ts, $lo);
}

sub toDomain {
my $name = shift;

    $name =~ tr/A-Z/a-z/;
    my $res = "";
    while ($name =~ /^([^.]*)\./) {
	$name = $';
	$res .= chr(length($1)).$1;
    }
    return $res.chr(length($name)).$name."\0";
}

package main;

sub usage {
    print STDERR "$0 -g <bits> <flags> <algorithm> <domain> <keyfile>\n";
    print STDERR " or\n";
    print STDERR "$0 [-t <ttl>] [<keyfile> ...] <input >output\n";
    exit(1);
}

sub findControl {
my $rec = shift;

    if (exists($rec->{control})) { return; }

    my $dom = $rec->{name};
    my $soa = exists($rec->{byType}->{6});
    if ($soa) {
	$rec->{control} = $dom;
	$rec->{zone}->{$dom} = $rec;
	push @main::zones, $dom;
	return;
    }

    my $anc = $dom;
    while ($anc =~ /^[^.]*\./) {
	$anc = $';
	if ($dom !~ /^\*\./ && exists($main::names{"*.$anc"})
		&& !exists($main::names{"*.$dom"})) {
	    print STDERR "Warning: wildcard *.$anc shadowed by $dom (see RFC-1034 sect. 4.3.3)!\n";
	}
	if (exists($main::names{$anc})) {
	    my $ctl_rec = $main::names{$anc};
	    &findControl($ctl_rec);
	    if (!exists($ctl_rec->{control})) {
		if (!$soa) { print STDERR "Warning: Out-of-bailiwick name '$dom' (oob parent)\n"; }
		return;
	    }
	    my $control = $ctl_rec->{control};
	    if ($ctl_rec->{byType}->{2}) { $control = $anc; }
	    $ctl_rec = $main::names{$control};
	    if (!$ctl_rec->{byType}->{6}) {
		# Most likely glue...
		if (!exists($rec->{byType}->{1})
			&& !exists($rec->{byType}->{28})) {
		    print STDERR "Warning: Out-of-bailiwick name '$dom' (below subdelegation)\n";
		}
	    } else {
		$rec->{control} = $control;
		$ctl_rec->{zone}->{$dom} = $rec;
	    }
	    return;
	}
    }
    print STDERR "Warning: Out-of-bailiwick name '$dom' (no parent)\n";
}

sub parseData {
my $in = shift;

    my $res = "";
    while ($in =~ /^(.*?)\\(\d\d\d)/) {
	$in = $';
	$res .= $1.chr(oct($2));
    }
    return $res.$in;
}

sub makeGenericRecord {
my ($dom, $type, $rdata, $ttl, $ts, $lo) = @_;

    print ":$dom:$type:";
    while (length($rdata)) {
	my $char = substr($rdata, 0, 1);
	$rdata = substr($rdata, 1);
	if ($char =~ /[0-9a-zA-Z +*.,\/=<>\@\$-]/) {
	    print $char;
	} else {
	    printf "\\%03o", ord($char);
	}
    }
    print ":$ttl:$ts:$lo\n";
}

sub getOrCreateRRs {
my $dom = shift;

    $dom =~ tr/A-Z/a-z/;
    if (!exists($main::names{$dom})) {
	$main::names{$dom} = new Records($dom);
    }
    return $main::names{$dom};
}

sub htons {
my $n = shift;

    return chr($n >> 8).chr($n & 0xff);
}

sub htonl {
my $n = shift;

    return &htons($n >> 16).&htons($n & 0xffff);
}

sub wireName {
my $name = shift;

    my $wire = "";
    while ($name =~ /^([^.]+)/) {
	$wire .= chr(length($1)).$1;
	$name = ($name eq $1) ? "" : substr($name, length($1) + 1);
    }
    return $wire."\0";
}

sub nsec3hash {
my ($name, $iter, $salt) = @_;

    my $dig = &wireName($name);
    while ($iter-- >= 0) {
	$dig = sha1($dig.$salt);
    }
    return $dig;
}

sub base32hex {
my $data = shift;

    my $buf = 0;
    my $bits = 0;
    my $res = "";
    while (length($data) > 0) {
	$buf = ($buf << 8) | ord($data);
	$data = substr($data, 1);
	$bits += 8;
	while ($bits >= 5) {
	    my $dig = ($buf >> ($bits-5)) & 0x1f;
	    $bits -= 5;
	    if ($dig < 10) {
	        $res .= $dig;
	    } else {
	        $res .= chr($dig + 87);
	    }
	}
    }
    if ($bits > 0) {
	$buf <<= (5 - $bits);
	$buf &= 0x1f;
	if ($buf < 10) {
	    $res .= $buf;
	} else {
	    $res .= chr($buf + 87);
	}
	$bits += 3;
	while ($bits > 0) {
	    if ($bits < 5) { $bits += 8; }
	    else { $res .= "="; $bits -= 5; }
	}
    }
    return $res;
}

sub tai2unix {
my $ts = shift;

    $ts =~ s/^40*//;
    return "0x$ts" - 10;
}

sub genTypeBitmaps {
    my %windows = ();
    if ($#_ > 0 || $#_ == 0 && $_[0] != 2) {
	# The type bitmaps includes all types except those contributed by NSEC3
	# itself, including the signature for the NSEC3. I. e. if there's at
	# least one record here (except for a single NS delegation), there'll
	# also be an RRSIG here, eventually.
	push @_, 46;
	@_ = sort @_;
    }
    foreach my $type (@_) {
	my $window = $type >> 8;
	$type &= 0xff;
	if (exists($windows{$window})) {
	    push @{$windows{$window}}, $type;
	} else {
	    $windows{$window} = [$type];
	}
    }
    my $tbm = "";
    foreach my $window (sort keys %windows) {
	my $wbm = "\0" x 32;
	foreach my $type (@{$windows{$window}}) {
	    substr($wbm, $type >> 3, 1) = chr(ord(substr($wbm, $type >> 3, 1)) | 1 << (7 - ($type & 7)));
	}
	$wbm =~ s/\0+$//;
	$tbm .= chr($window).chr(length($wbm)).$wbm;
    }
    return $tbm;
}

sub gen_pubkey_data {
my ($n, $e, $flags, $alg, $dom) = @_;

    my $e_bin = $e->to_bin();
    $e_bin =~ s/^\0+//;
    my $n_bin = $n->to_bin();
    $n_bin =~ s/^\0+//;

    my $pubkey = chr(length($e_bin)).$e_bin.$n_bin;
    my $keytag = $flags + $alg + 3 * 256; # protocol is always 3
    for (my $i = length($pubkey) - 1; $i >= 0; $i--) {
	$keytag += ord(substr($pubkey, $i)) * (($i & 1) ? 1 : 256);
    }
    if ($alg > 0) {
	$keytag += $keytag >> 16;
	$keytag &= 0xffff;
    }
    $dom =~ tr/A-Z/a-z/;
    my $digest = sha1_hex(&wireName($dom).&htons($flags).chr(3).chr($alg).$pubkey);
    return ($keytag, $pubkey, $digest);
}

sub addA {
my ($dom, $ip, $ttl, $ts, $lo) = @_;

    if ($ip eq "") { return; }
    my $rec = &getOrCreateRRs($dom);
    $rec->addA($ip, $ttl, $ts, $lo);
}

sub addPTR {
my ($ip, $dom, $ttl, $ts, $lo) = @_;

    my $arpa;
    if ($ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
	$arpa = "$4.$3.$2.$1.in-addr.arpa";
    } elsif ($ip =~ /^[0-9a-f]{32}$/i) {
	$ip =~ tr/A-Z/a-z/;
	$arpa = "ip6.arpa";
	while ($ip =~ /^./) {
	    $ip = $';
	    $arpa = "$&.$arpa";
	}
    } else {
	print STDERR "Warning: ignoring unparsable IP address '$ip'\n";
	return;
    }
    my $rec = getOrCreateRRs($arpa);
    $rec->addPTR($dom, $ttl, $ts, $lo);
}

sub addKey {
my ($file) = @_;

    open(KEYFILE, "<$file") or die("Can't read $file either:");
    my $rsa = Crypt::OpenSSL::RSA->new_private_key(join("", <KEYFILE>));
    close KEYFILE;
    if (!$rsa) {
	print STDERR "Failed to read key from $file!\n";
	exit(1);
    }
    my ($n, $e, $x1, $x2, $x3, $x4, $x5, $x6) = $rsa->get_key_parameters();
    $x1 = $x2 = $x3 = $x4 = $x5 = $x6 = 0; # get rid of private stuff
    my ($keytag, $keydata, $fp) = &gen_pubkey_data($n, $e, 0, 0, "");
    $main::keys{$keydata} = { key => $rsa, basetag => $keytag };
}

sub genkey {
my ($bits, $flags, $alg, $dom, $file) = @_;

    if ($bits < 1024 || $bits > 4096) {
	print STDERR "ERROR: Keys of less than 1024 or more than 4096 bits are not supported!\n";
	exit 1;
    }

    if ($alg != 7 && $alg != 8 && $alg != 10) {
	print STDERR "ERROR: $0 only supports algorithms 7 (RSA-SHA1), 8 (RSA-SHA256)\nand 10 (RSA-SHA512).\n";
	exit 1;
    }

    if (sysopen(KEYFILE, $file, O_CREAT|O_EXCL|O_WRONLY, 0600)) {
	my $rsa = Crypt::OpenSSL::RSA->generate_key($bits);
	print KEYFILE $rsa->get_private_key_string();
	my ($n, $e, $x1, $x2, $x3, $x4, $x5, $x6) = $rsa->get_key_parameters();
	$x1 = $x2 = $x3 = $x4 = $x5 = $x6 = 0; # get rid of private stuff
	my ($keytag, $keydata, $fp) = &gen_pubkey_data($n, $e, $flags, $alg, $dom);
	print KEYFILE "#K$dom:$flags:3:$alg:".encode_base64($keydata, "").":::\n";
	print KEYFILE "#D$dom:$keytag:$alg:1:${fp}:::\n";
	close KEYFILE;
    } else {
	print STDERR "Warning: couldn't create $file: $!\n";
	print STDERR "Attempting to read key...\n";
	open(KEYFILE, "<$file") or die("Can't read $file either:");
	my $rsa = Crypt::OpenSSL::RSA->new_private_key(join("", <KEYFILE>));
	close KEYFILE;
	if (!$rsa) {
	    print STDERR "Failed to read key from $file!\n";
	    exit(1);
	}
	my ($n, $e, $x1, $x2, $x3, $x4, $x5, $x6) = $rsa->get_key_parameters();
	$x1 = $x2 = $x3 = $x4 = $x5 = $x6 = 0; # get rid of private stuff
	my ($keytag, $keydata, $fp) = &gen_pubkey_data($n, $e, $flags, $alg, $dom);
	print "#K$dom:$flags:3:$alg:".encode_base64($keydata, "").":::\n";
	print "#D$dom:$keytag:$alg:1:${fp}:::\n";
    }
    exit 0;
}

=pod

=head1 NAME

tinydns-sign - Signs records in L<tinydns-data(8)> files

=head1 SYNOPSIS

    tinydns-sign -g bits flags algorithm domain keyfile

    tinydns-sign [-t ttl] [keyfile ...] <infile >outfile

=head1 DESCRIPTION

The first form is used to generate a public/private RSA key pair with a
modulus of length I<bits>. If F<keyfile> exists, tinydns-sign will try to
read a private key from the file and print DS and DNSKEY pseudo-records for
the corresponding public key on stdout. If F<keyfile> does not exist,
tinydns-sign will generate a new key pair and write the key plus the
corresponding pseudo-records to F<keyfile>.

In the second form, tinydns-sign reads key pairs from each given F<keyfile>.
It then reads a L<tinydns-data(8)> file from STDIN and writes the same
file to STDOUT, with the following modifications:

=over

=item * It will delete all generic records with RRTYPE DS (43), RRSIG (46),
DNSKEY (48), NSEC3(50), NSEC3PARAM(51) and private types 65281 and 65282.

=item * It will turn each . record into a Z record and a & record.

=item * It will adjust the serial number of all Z records to the current time,
unless the serial number begins with two zeroes. Note that an SOA must have a
fixed serial for generating a matching RRSIG record.

=item * It will create new DS, DNSKEY and NSEC3PARAM records from each
corresponding pseudo record (see below) present in the file.

=item * It will create NSEC3 records for all names in all zones that have at
least one DNSKEY and NSEC3PARAM in the file.

=item * It will create a generic record with type 65281 for each name
(including empty non-terminals) containing the owner of its matching NSEC3 RR.

=item * It will create generic records with type 65282 for each hex digit (i.
e. 0-9a-f) below the zone apex containing all NSEC3 hashes starting with that
digit.

=item * It will create RRSIG records for all RR-sets in all zones that have at
least one DNSKEY in the file. If both DNSKEYS with and without the SEP flag set
are present, then those with the SEP flag will be used only for RRSIGs on
DNSKEY RRs and those without the SEP flag will be used for the remaining
RR-sets. Otherwise, RRSIGs will be created using all DNSKEYs.

RRSIGs will be valid beginning one hour in the past and ending at (now + I<ttl>)
seconds. I<ttl> defaults to 432000 (5 days).

=back

=head2 Pseudo-Records

Pseudo-records are records defined in a syntax that's only understood by
tinydns-sign. To L<tinydns-data(8)> they look like comments, i. e. they are
ignored.

tinydns-sign will create one or more generic records for each pseudo-record.
All generic records with an RR-type for which a pseudo-record can be defined
are deleted from the input. (Otherwise, removing a pseudo-record would not
result in removal of the corresponding generic record.)

In contrast to standard tinydns-data behaviour, trailing colons in
pseudo-records are B<not> optional.

Currently, pseudo-records are defined for the following RR-types:

=over

=item * #Kname:flags:proto:algorithm:key:ttl:timestamp:lo

This generates a DNSKEY record for I<name>. I<flags>. I<proto> and I<algorithm>
are decimal numbers. At the time of writing, I<proto> must be 3. tinydns-sign
only supports I<algorithm>s 7 (RSA-SHA1), 8 (RSA-SHA256) and 10 (RSA-SHA512).
I<key> is base-64 encoded key material, depending on the selected
I<algorithm>. I<ttl>, I<timestamp> and I<lo> are as usual.

It is an error to have a DNSKEY pseudo-record in the input without a
corresponding F<keyfile> containing the matching private key.

=item * #Dname:tag:algorithm:digest:fingerprint:ttl:timestamp:lo

This generates a DS record for I<name>. I<tag> is the key tag, I<algorithm>
specifies the algorithm of the referenced key and I<digest> is the digest type
(all in decimal).  I<fingerprint> is the hex-encoded actual digest value
(omitting leading/trailing zeroes is not permitted!). I<ttl>, I<timestamp> and
I<lo> are as usual.

=item * #Pname:algorithm:flags:iter:len:salt:ttl:timestamp:lo

This generates an NSEC3PARAM record for I<name> with the given I<algorithm>,
I<flags>, I<iter>ation count, salt I<len>gth and I<salt>. If I<salt> is empty,
a new random salt with the given salt I<len>gth (4 bytes if I<len> is empty)
will be generated. If I<salt> is non-empty, it must be a string of hex digits
with even length. The salt length is derived from the given salt value, i. e.
I<len> is ignored in that case.  I<ttl>, I<timestamp> and I<lo> are as usual.

tinydns-sign currently only supports I<algorithm> 1 (SHA-1). At the time of
writing, I<flags> is defined to be 0, and the I<iter>ation count is limited
depending on the key length (see L<RFC-5155>).

=back

=head1 EXIT STATUS

tinydns-sign will exit with status 0 if it thinks all went well. Warning
messages will not trigger a nonzero exit status.

tinydns-sign will exit with nonzero status if an error occurred. In this case,
the output is most likely incomplete and should not be used to replace an
input file.

=head1 SEE ALSO

L<tinydns-data(8)>,
L<RFC-4034|http://tools.ietf.org/html/rfc4034>,
L<RFC-4035|http://tools.ietf.org/html/rfc4035>,
L<RFC-5155|http://tools.ietf.org/html/rfc5155>

=head1 LIMITATIONS

=over

=item * Location code handling is incomplete in that location codes must be
present for all RRs in a zone, or for none at all.

=item * Timestamps are currently mostly ignored, i. e. signatures will happily
outlive the RR-sets which they sign.

=item * It is currently not possible to protect the private keys with a
passphrase.

=item * It is not possible to have a signed zone and a signed child zone in
the same data file.

=item * NSEC3 RRs with Opt-Out child zones are not supported.

=item * The pseudo-RRs with type 65282 contain a list of hash values. The list
cannot grow bigger than 65kBytes (about 3270 hashes). This is not a problem
for a typical domain, but it would be a problem if tinydns were to serve the
.de zone, for example. Also, the list is searched sequentially, which can
cause a performance impact long before this limit is reached.

=back

=head1 CAVEATS

=over

=item * The system clock should be reasonably close to UTC (i. e. within a few minutes).

=item * Stock tinydns/axfrdns will happily work with signed data.cdb files,
but they will not produce correct DNSSEC responses!

=item * If a zone contains both keys with and without the SEP flag, you must
make sure that both key sets cover the same set of algorithms. This is due to
a requirement in RFC-4035 section 2.2.

=back

=head1 AUTHOR

(C) 2012 Peter Conrad L<mailto:conrad@quisquis.de>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

=cut

