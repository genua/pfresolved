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
use Errno;
use File::Basename;
use Socket;
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
	$args{test} ||= basename($args{testfile} || "");
	$args{up} ||= "nsd started";

	my $self = Proc::new($class, %args);

	$self->conf();
	$self->root();
	$self->zone();

	return $self;
}

sub conf {
	my $self = shift;

	open(my $fh, '>', $self->{conffile}) or die ref($self),
	    " config file '$self->{conffile}' create failed: $!";
	print $fh "# test $self->{test}\n";
	print $fh "server:\n";
	print $fh "	chroot: \"\"\n";
	if ($self->{listen}{domain} && $self->{listen}{domain} == AF_INET) {
		print $fh "	do-ip4: yes\n";
		print $fh "	do-ip6: no\n";
	}
	if ($self->{listen}{domain} && $self->{listen}{domain} == AF_INET6) {
		print $fh "	do-ip4: no\n";
		print $fh "	do-ip6: yes\n";
	}
	print $fh "	ip-address: $self->{addr}\n";
	print $fh "	pidfile: \"\"\n";
	print $fh "	port: $self->{port}\n";
	if ($self->{tls}) {
		print $fh "	tls-port: $self->{port}\n";
		print $fh "	tls-service-key: \"server.key\"\n";
		print $fh "	tls-service-pem: \"server.crt\"\n";
	}
	print $fh "	verbosity: 3\n";
	print $fh "	zonesdir: .\n";
	print $fh "zone:\n";
	# provide root zone for testing dnssec validation
	print $fh "	name: .\n";
	print $fh "	zonefile: root.zone.signed\n";
	print $fh "zone:\n";
	# libunbound does not process invalid domain
	print $fh "	name: regress.\n";
	my $signed = $self->{dnssec} ? ".signed" : "";
	print $fh "	zonefile: regress.zone$signed\n";
}

sub root {
	my $self = shift;

	my $serial = time();
	open(my $fh, '>', "root.zone") or die ref($self),
	    " zone file 'root.zone' create failed: $!";
	print $fh "; test $self->{test}\n";
	print $fh "\$ORIGIN	.\n";
	print $fh "\$TTL	86400\n";
	print $fh "\@	IN	SOA	localhost root.localhost (\n";
	print $fh "		$serial	; serial number\n";
	print $fh "		7200		; refresh\n";
	print $fh "		600		; retry\n";
	print $fh "		86400		; expire\n";
	print $fh "		3600		; minimum TTL\n";
	print $fh "	)\n";
	print $fh "regress	IN	NS	localhost\n";
	if ($self->{dnssec} || $self->{dnssec_delegation}) {
	    # root zone contains delegation signer of regress zone
	    open(my $ds, '<', "regress-ksk.ds") or die ref($self),
		" open file 'regress-ksk.ds' failed: $!";
	    print $fh (<$ds>);
	}
	{
	    # every signed zone contains its own public keys
	    open(my $kk, '<', "root-ksk.key") or die ref($self),
		" open file 'root-ksk.key' failed: $!";
	    print $fh (<$kk>);
	    open(my $zk, '<', "root-zsk.key") or die ref($self),
		" open file 'root-zsk.key' failed: $!";
	    print $fh (<$zk>);
	}
	close($fh);

	{
	    # root zone is always signed
	    my @cmd = qw(/usr/local/bin/ldns-signzone -b -n
		root.zone root-zsk root-ksk);
	    system(@cmd) and die ref($self),
		"sign root zone command '@cmd' failed: $?";
	}
}

sub zone {
	my $self = shift;
	my %args = @_;
	$args{serial} ||= $self->{serial} || time();
	$self->{record_list} = $args{record_list} if $args{record_list};

	open(my $fh, '>', "regress.zone") or die ref($self),
	    " zone file 'regress.zone' create failed: $!";
	print $fh "; test $self->{test}\n";
	print $fh "\$ORIGIN	regress.\n";
	print $fh "\$TTL	86400\n";
	print $fh "\@	IN	SOA	localhost root.localhost (\n";
	print $fh "		$args{serial}	; serial number\n";
	print $fh "		7200		; refresh\n";
	print $fh "		600		; retry\n";
	print $fh "		86400		; expire\n";
	print $fh "		3600		; minimum TTL\n";
	print $fh "	)\n";
	foreach my $r (@{$self->{record_list} || []}) {
		print $fh "$r\n";
	}
	if ($self->{dnssec} || $self->{dnssec_key}) {
	    # every signed zone contains its own public keys
	    open(my $kk, '<', "regress-ksk.key") or die ref($self),
		" open file 'regress-ksk.key' failed: $!";
	    print $fh (<$kk>);
	    open(my $zk, '<', "regress-zsk.key") or die ref($self),
		" open file 'regress-zsk.key' failed: $!";
	    print $fh (<$zk>);
	}
	close($fh);

	if ($self->{dnssec}) {
		my @cmd = qw(/usr/local/bin/ldns-signzone -b -n
		    regress.zone regress-zsk regress-ksk);
		system(@cmd) and die ref($self),
		    "sign regress zone command '@cmd' failed: $?";
	}
}

sub sighup {
	my $self = shift;

	kill(HUP => $self->{pid})
	    and return;

	my @sudo = split(' ', $ENV{SUDO});
	@sudo && $!{EPERM}
	    or die ref($self), " kill HUP child '$self->{pid}' failed: $!";

	# sudo is enabled and kill failed with operation not permitted
	my @cmd = (@sudo, '/bin/kill', '-HUP', $self->{pid});
	system(@cmd)
	    and die ref($self), " command '@cmd' failed: $?";
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
