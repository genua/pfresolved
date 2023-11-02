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

package Pfresolved;
use parent 'Proc';
use Carp;
use Cwd;
use File::Basename;
use Sys::Hostname;

sub new {
	my $class = shift;
	my %args = @_;
	$args{ktraceexec} = "ktrace" if $args{ktrace};
	$args{ktraceexec} = $ENV{KTRACE} if $ENV{KTRACE};
	$args{ktracefile} ||= "pfresolved.ktrace";
	$args{logfile} ||= "pfresolved.log";
	$args{up} ||= "forwarder starting";
	$args{down} ||= "parent terminating";
	$args{func} = sub { Carp::confess "$class func may not be called" };
	$args{execfile} ||= $ENV{PFRESOLVED} ? $ENV{PFRESOLVED} : "pfresolved";
	$args{conffile} ||= "pfresolved.conf";
	my $self = Proc::new($class, %args);

	my $test = basename($self->{testfile} || "");
	open(my $fh, '>', $self->{conffile}) or die ref($self),
	    " config file '$self->{conffile}' create failed: $!";
	print $fh "# test $test\n";
	print $fh "regress-pfresolved {\n";
	print $fh  "\n}\n";

	return $self;
}

sub child {
	my $self = shift;
	my @sudo = $ENV{SUDO} ? $ENV{SUDO} : "env";

	my @pkill = (@sudo, "pkill", "-KILL", "-x", "pfresolved");
	my @pgrep = ("pgrep", "-x", "pfresolved");
	system(@pkill) && $? != 256
	    and die ref($self), " system '@pkill' failed: $?";
	while ($? == 0) {
		print STDERR "pfresolved still running\n";
		system(@pgrep) && $? != 256
		    and die ref($self), " system '@pgrep' failed: $?";
	}
	print STDERR "pfresolved not running\n";

	my @ktrace;
	@ktrace = ($self->{ktraceexec}, "-i", "-f", $self->{ktracefile})
	    if $self->{ktraceexec};
	my @cmd = (@sudo, @ktrace, $self->{execfile}, "-dvv",
	    "-f", $self->{conffile});
	print STDERR "execute: @cmd\n";
	exec @cmd;
	die ref($self), " exec '@cmd' failed: $!";
}

1;
