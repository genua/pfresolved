#	$OpenBSD$

# Copyright (c) 2010-2023 Alexander Bluhm <bluhm@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use strict;
use warnings;
use IO::Socket::IP;

sub find_ports {
	my %args = @_;
	my $num    = delete $args{num}    // 1;
	my $domain = delete $args{domain} // AF_INET;
	my $addr   = delete $args{addr}   // "127.0.0.1";
	my $proto  = delete $args{proto}  // "udp";
	$proto = "tcp" if $proto eq "tls";

	my @sockets = (1..$num);
	foreach my $s (@sockets) {
		$s = IO::Socket::IP->new(
		    Domain    => $domain,
		    LocalAddr => $addr,
		    Proto     => $proto,
		) or die "find_ports: create and bind socket failed: $!";
	}
	my @ports = map { $_->sockport() } @sockets;

	return wantarray ? @ports : $ports[0];
}

sub check_logs {
	my ($n, $d, $s, %args) = @_;

	return if $args{nocheck};

	check_loggrep($n, $d, $s, %args);
}

sub compare($$) {
	local $_ = $_[1];
	if (/^\d+/) {
		return $_[0] == $_;
	} elsif (/^==(\d+)/) {
		return $_[0] == $1;
	} elsif (/^!=(\d+)/) {
		return $_[0] != $1;
	} elsif (/^>=(\d+)/) {
		return $_[0] >= $1;
	} elsif (/^<=(\d+)/) {
		return $_[0] <= $1;
	} elsif (/^~(\d+)/) {
		return $1 * 0.8 <= $_[0] && $_[0] <= $1 * 1.2;
	}
	die "bad compare operator: $_";
}

sub check_loggrep {
	my ($n, $d, $s, %args) = @_;

	my %name2proc = (nsd => $n, pfresolved => $d, pfctl => $s);
	foreach my $name (qw(nsd pfresolved pfctl)) {
		my $p = $name2proc{$name} or next;
		my $pattern = $args{$name}{loggrep} or next;
		$pattern = [ $pattern ] unless ref($pattern) eq 'ARRAY';
		foreach my $pat (@$pattern) {
			if (ref($pat) eq 'HASH') {
				while (my($re, $num) = each %$pat) {
					my @matches = $p->loggrep($re);
					compare(@matches, $num)
					    or die "$name matches '@matches': ",
					    "'$re' => $num";
				}
			} else {
				$p->loggrep($pat)
				    or die "$name log missing pattern: '$pat'";
			}
		}
	}
}

1;
