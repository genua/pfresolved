# Write localhost into pfresolved config.
# Wait until pfresolved creates table regress-pfresolved.
# Read IP addresses from pf table with pfctl.
# Check that pfresolved added 127.0.0.1 and ::1.
# Check that table contains 127.0.0.1 and ::1.

use strict;
use warnings;

our %args = (
    pfresolved => {
	address_list => [qw(localhost.)],  # must resolve A and AAAA
	loggrep => {
	    qr{added: 127.0.0.1/32,} => 1,
	    qr{added: ::1/128,} => 1,
	},
    },
    pfctl => {
	updated => [1, 1],
	loggrep => {
	    qr/^   127.0.0.1$/ => 1,
	    qr/^   ::1$/ => 1,
	},
    },
);

1;
