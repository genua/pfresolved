# Write the same address in normal and negated form into pfresolved config.
# Start pfresolved.
# Check that configuration parsing fails.

use strict;
use warnings;
use Socket;

our %args = (
    pfresolved => {
        address_list => [
            "192.0.2.1",
            "! 192.0.2.1",
        ],
        loggrep => {
            qr{the same address cannot be specified in normal and negated form} => 1,
        },
        expected_status => 1,
        down => "parent: parsing configuration failed",
    },
);

1;
