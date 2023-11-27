# Create zone file with A and AAAA records in zone regress.
# Start nsd with zone file listening on 127.0.0.1.
# Write hosts of regress zone into pfresolved config.
# Start pfresolved with nsd as resolver.
# Pfresolved is provided with wrong hostname to verify server cert.
# Wait until pfresolved reports lookup failure.
# Check that pfresolved added no addresses.
# Check that pfresolved reports "certificate verify failed".

use strict;
use warnings;
use Socket;

our %args = (
    nsd => {
	listen => { proto => "tls" },
	record_list => [
	    "foo	IN	A	192.0.2.1",
	    "bar	IN	AAAA	2001:DB8::1",
	    "foobar	IN	A	192.0.2.2",
	    "foobar	IN	AAAA	2001:DB8::2",
	],
	loggrep => {
	    qr/listen on ip-address 127.0.0.1\@\d+ \(tcp\)/ => 1,
	},
    },
    pfresolved => {
	address_list => [ map { "$_.regress." } qw(foo bar foobar) ],
	hostname => "badhost",
	loggrep => {
	    qr/-r 127.0.0.1\@\d+#badhost/ => 1,
	    qr/error: ssl handshake failed crypto error:.*/.
		qr/certificate verify failed/ => '>=1',
	    qr{added: 192.0.2.1/32,} => 0,
	    qr{added: 2001:db8::1/128,} => 0,
	    qr{added: 192.0.2.2/32,} => 0,
	    qr{added: 2001:db8::2/128,} => 0,
	},
    },
    pfctl => {
	updated => [1, 0],
	func => sub {
	    my $self = shift;
	    my $pfresolved = $self->{pfresolved};
	    my $failed = qr/query for .* failed/;
	    my $timeout = 15;
	    $pfresolved->loggrep($failed, $timeout)
		or die ref($self), " no '$failed' in $pfresolved->{logfile}",
		    " after $timeout seconds";
	},
    },
);

1;
