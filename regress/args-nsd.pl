# Create zone file with A and AAAA records in zone regress.
# Start nsd with zone file listening on 127.0.0.1.
# Write hosts of regress zone into pfresolved config.
# Start pfresolved with nsd as resolver.
# Wait until pfresolved creates table regress-pfresolved.
# Read IP addresses from pf table with pfctl.
# Check that pfresolved added IPv4 and IPv6 addresses.
# Check that pf table contains all IPv4 and IPv6 addresses.

use strict;
use warnings;

our %args = (
    nsd => {
	record_list => [
	    "foo	IN	A	192.0.2.1",
	    "bar	IN	AAAA	2001:DB8::1",
	    "foobar	IN	A	192.0.2.2",
	    "foobar	IN	AAAA	2001:DB8::2",
	],
    },
    pfresolved => {
	address_list => [ map { "$_.regress." } qw(foo bar foobar) ],
	loggrep => {
	    qr{added: 192.0.2.1/32,} => 1,
	    qr{added: 2001:db8::1/128,} => 1,
	    qr{added: 192.0.2.2/32,} => 1,
	    qr{added: 2001:db8::2/128,} => 1,
	},
    },
    pfctl => {
	updated => [4, 1],
	loggrep => {
	    qr/^   192.0.2.[12]$/ => 2,
	    qr/^   2001:db8::[12]$/ => 2,
	},
    },
);

1;
