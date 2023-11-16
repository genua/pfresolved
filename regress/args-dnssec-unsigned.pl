# Test DNSSEC with unsigned zone below root.

# Create signed root zone with delegation but without delegation signer.
# Create zone file that is not signed with A and AAAA records in zone regress.
# Start nsd with unsigned zone file listening on 127.0.0.1.
# Write hosts of regress zone into pfresolved config.
# Start pfresolved with nsd as resolver, dnssec level 2, and trust anchor root.
# Wait until pfresolved creates table regress-pfresolved.
# Read IP addresses from pf table with pfctl.
# Check that pfresolved added IPv4 and IPv6 addresses.
# Check that pfresolved logged not secure when receiving dns.

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
	dnssec_level => 2,
	address_list => [ map { "$_.regress." } qw(foo bar foobar) ],
	loggrep => {
	    qr/result for .* secure: 0,/ => 6,
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
