#       $OpenBSD$

# Copyright (c) 2023 Alexander Bluhm <bluhm@openbsd.org>
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

package Pfctl;
use parent 'Proc';
use Carp;

sub new {
	my $class = shift;
	my %args = @_;
	$args{func} ||= \&func;
	$args{logfile} ||= "pfctl.log";
	$args{up} ||= "Table";

	my $self = Proc::new($class, %args);

	return $self;
}

sub child {
	my $self = shift;
	my $timeout = $self->{timeout} || 15;
	my $updated = $self->{updated};
	my $pfresolved = $self->{pfresolved};

	# make it possible to match on /added: 2,/ by passing array
	my ($updates, $added) = ($updated->[0], $updated->[1]);

	my $table = qr/updated addresses for pf table .*: added: $added,/;
	my $tomsg = $timeout ? " after $timeout seconds" : "";
	my $upmsg = $updates ? " for $updates times" : "";
	$pfresolved->loggrep($table, $timeout, $updates)
	    or die ref($self), " no '$table' in $pfresolved->{logfile}",
		$tomsg, $upmsg;

	open(STDOUT, '>&', \*STDERR)
	    or die ref($self), " dup STDOUT failed: $!";
}

sub func {
	my $self = shift;

	$self->show();
}

sub show {
	my $self = shift;
	my @sudo = $ENV{SUDO} ? $ENV{SUDO} : ();

	my @cmd = (@sudo, qw(/sbin/pfctl -t regress-pfresolved -T show));
	system(@cmd)
	    and die die ref($self), " command '@cmd' failed: $?";
}

1;
