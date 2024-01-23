# Write negated network into pfresolved config.
# Start pfresolved.
# Check that configuration parsing fails.

use strict;
use warnings;
use Socket;

our %args = (
    pfresolved => {
        address_list => [
            "! 192.0.2.1/24",
        ],
        loggrep => {
            qr{negation is not allowed for networks} => 1,
        },
        expected_status => 1,
        down => "parent: parsing configuration failed",
    },
);

1;
