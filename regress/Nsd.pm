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

package Nsd;
use parent 'Proc';
use Carp;
use File::Basename;
use Sys::Hostname;

sub new {
	my $class = shift;
	my %args = @_;
	$args{conffile} ||= "nsd.conf";
	$args{down} ||= "shutting down";
	$args{func} = sub { Carp::confess "$class func may not be called" };
	$args{ktraceexec} = "ktrace" if $args{ktrace};
	$args{ktraceexec} = $ENV{KTRACE} if $ENV{KTRACE};
	$args{ktracefile} ||= "nsd.ktrace";
	$args{logfile} ||= "nsd.log";
	$args{serial} ||= time();
	$args{up} ||= "nsd started";

	my $self = Proc::new($class, %args);

	my $test = basename($self->{testfile} || "");
	open(my $fh, '>', $self->{conffile}) or die ref($self),
	    " config file '$self->{conffile}' create failed: $!";
	print $fh "# test $test\n";
	print $fh "server:\n";
	print $fh "	chroot: \"\"\n";
	print $fh "	ip-address: $self->{addr}\n";
	print $fh "	pidfile: \"\"\n";
	print $fh "	port: $self->{port}\n";
	print $fh "	verbosity: 3\n";
	print $fh "	zonesdir: .\n";
	print $fh "zone:\n";
	# libunbound does not process invalid domain
	print $fh "	name: regress.\n";
	print $fh "	zonefile: nsd.zone\n";

	open(my $fz, '>', "nsd.zone") or die ref($self),
	    " zone file 'nsd.zone' create failed: $!";
	print $fz "; test $test\n";
	print $fz "\$ORIGIN	regress.\n";
	print $fz "\$TTL	86400\n";
	print $fz "\@	IN	SOA	pfresolved root.pfresolved (\n";
	print $fz "		$args{serial}	; serial number\n";
	print $fz "		7200		; refresh\n";
	print $fz "		600		; retry\n";
	print $fz "		86400		; expire\n";
	print $fz "		3600		; minimum TTL\n";
	print $fz "	)\n";
	foreach my $r (@{$self->{record_list} || []}) {
		print $fz "$r\n";
	}

	return $self;
}

sub child {
	my $self = shift;
	my @sudo = $ENV{SUDO} ? $ENV{SUDO} : ();

	my @ktrace;
	@ktrace = ($self->{ktraceexec}, "-i", "-f", $self->{ktracefile})
	    if $self->{ktraceexec};
	my @cmd = (@sudo, @ktrace, "/usr/sbin/nsd", "-d",
	    "-c", $self->{conffile});
	print STDERR "execute: @cmd\n";
	exec @cmd;
	die ref($self), " exec '@cmd' failed: $!";
}

1;
