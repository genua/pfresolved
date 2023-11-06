#!/usr/bin/perl
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

use Nsd;
use Pfresolved;
use Pfctl;
require 'funcs.pl';

sub usage {
	die "usage: pfresolved.pl [test-args.pl]\n";
}

my $testfile;
our %args;
if (@ARGV and -f $ARGV[-1]) {
	$testfile = pop;
	do $testfile
	    or die "Do test file '$testfile' failed: ", $@ || $!;
}
@ARGV == 0 or usage();

my $n = Nsd->new(
    addr		=> $args{nsd}{listen}{addr} //= "127.0.0.1",
    port		=> scalar find_ports(%{$args{nsd}{listen}}),
    tls			=> ($args{nsd}{listen}{proto} // "") eq "tls",
    %{$args{nsd}},
    testfile		=> $testfile,
) if $args{nsd};
my $d = Pfresolved->new(
    addr		=> $n && $n->{addr},
    port		=> $n && $n->{port},
    tls			=> $n && $n->{tls},
    %{$args{pfresolved}},
    testfile		=> $testfile,
);
my $s = Pfctl->new(
    %{$args{pfctl}},
    pfresolved		=> $d,
) if $args{pfctl};

$n->run->up if $n;
$d->run->up;
$s->run->up if $s;

$s->down if $s;
$d->kill_child->down;
$n->kill_child->down if $n;

check_logs($n, $d, $s, %args);
