# Test DNSSEC with unsigned zone without signatures below root.

# Create signed root zone with delegation signer for regress.
# Create zone file that is not signed with A and AAAA records in zone regress.
# Start nsd with unsigned zone file listening on 127.0.0.1.
# Write hosts of regress zone into pfresolved config.
# Start pfresolved with nsd as resolver, dnssec level 2, and trust anchor root.
# Wait until pfresolved is starting new resolve request after failure.
# Read IP addresses from pf table with pfctl.
# Check that pf table contains neither IPv4 nor IPv6 addresses.
# Check that pfresolved logged "validation failure" and "no signatures".

use strict;
use warnings;

our %args = (
    nsd => {
	dnssec_delegation => 1,
	dnssec_key => 1,
	record_list => [
	    "foo	IN	A	192.0.2.1",
	    "bar	IN	AAAA	2001:DB8::1",
	    "foobar	IN	A	192.0.2.2",
	    "foobar	IN	AAAA	2001:DB8::2",
	],
    },
    pfresolved => {
	dnssec_level => 2,
	address_list => [ map { "$_.regress." } qw(foo bar foobar) ],
	loggrep => {
	    qr/result for .*: validation failure .* no signatures/ => 6
	},
    },
    pfctl => {
	updated => [1, 0],
	func => sub {
		my $self = shift;
		my $pfresolved = $self->{pfresolved};

		my $restart = qr/starting new resolve request/;
		my $timeout = 15;
		$pfresolved->loggrep($restart, $timeout) or die ref($self),
		    " no '$restart' in $pfresolved->{logfile}",
		    " after $timeout seconds";

		$self->show();
	    },
	loggrep => {
	    qr/^   192.0.2.[12]$/ => 0,
	    qr/^   2001:db8::[12]$/ => 0,
	},
    },
);

1;
