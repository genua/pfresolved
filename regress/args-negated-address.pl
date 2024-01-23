# Create zone file with A and AAAA records in zone regress.
# Start nsd with zone file listening on 127.0.0.1.
# Write hosts of regress zone into pfresolved config.
# Write negated addresses for hosts in regress zone into pfresolved config.
# Start pfresolved with nsd as resolver.
# Wait until pfresolved creates table regress-pfresolved.
# Read IP addresses from pf table with pfctl.
# Check that pfresolved resolved IPv4 and IPv6 addresses.
# Check that pf table only contains the negated IPv4 and IPv6 addresses.

use strict;
use warnings;
use Socket;

our %args = (
    nsd => {
        record_list => [
            "foo        IN      A       192.0.2.1",
            "foo        IN      AAAA    2001:DB8::1",
        ],
    },
    pfresolved => {
        address_list => [
            "foo.regress.",
            "! 192.0.2.1",
            "! 2001:DB8::1",
        ],
        loggrep => {
            qr{added: 192.0.2.1/32,} => 1,
            qr{added: 2001:db8::1/128,} => 1,
        },
    },
    pfctl => {
        updated => [2, 0],
        loggrep => {
            qr/^  !192.0.2.1$/ => 1,
            qr/^   192.0.2.1$/ => 0,
            qr/^  !2001:db8::1$/ => 1,
            qr/^   2001:db8::1$/ => 0,
        },
    },
);

1;
