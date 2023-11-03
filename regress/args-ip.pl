# Write constant IP addresses into pfresolved config.
# Wait until pfresolved creates table regress-pfresolved.
# Read IP addresses from pf table with pfctl.
# Check that output IP is the same as input IP.

use strict;
use warnings;

our %args = (
    pfresolved => {
	address_list => [qw(192.0.2.1 2001:DB8::1)],  # documentation IPs
    },
    pfctl => {
	loggrep => {
	    qr/^   192.0.2.1$/ => 1,
	    qr/^   2001:db8::1$/ => 1,
	},
    },
);

1;
