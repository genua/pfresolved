# Create zone file with A and AAAA records in zone regress.
# Start nsd with zone file with TTL 2 seconds and listening on 127.0.0.1.
# Write hosts of regress zone into pfresolved config.
# Start pfresolved with nsd as resolver.
# Wait until pfresolved creates table regress-pfresolved.
# Write new zone file with all adresses changed.
# Wait until TTL has expired and pfresolved has renewed adresses.
# Read IP addresses from pf table with pfctl.
# Check that pfresolved added IPv4 and IPv6 addresses.
# Check that pf table contains new IPv4 and IPv6 addresses with short TTL.
# Check that pf table contains old IPv4 and IPv6 addresses with default TTL.
# Check that pfresolved removed IPv4 and IPv6 addresses with short TTL.

use strict;
use warnings;
use Socket;

our %args = (
    nsd => {
	record_list => [
	    "foo		A	192.0.2.1",
	    "bar		AAAA	2001:DB8::1",
	    "foobar	2	A	192.0.2.2",
	    "foobar	2	AAAA	2001:DB8::2",
	],
    },
    pfresolved => {
	address_list => [ map { "$_.regress." } qw(foo bar foobar) ],
	min_ttl => 1,
	loggrep => {
	    qr/-m 1/ => 1,
	    qr{added: 192.0.2.1/32,} => 1,
	    qr{added: 2001:db8::1/128,} => 1,
	    qr{added: 192.0.2.2/32,} => 1,
	    qr{added: 2001:db8::2/128,} => 1,
	    qr/starting new resolve request for .* in 3 seconds/ => 2,
	    qr{removed: 192.0.2.1/32} => 0,
	    qr{removed: 2001:db8::1/128} => 0,
	    qr{removed: 192.0.2.2/32$} => 1,
	    qr{removed: 2001:db8::2/128$} => 1,
	    qr{added: 192.0.2.10/32,} => 0,
	    qr{added: 2001:db8::10/128,} => 0,
	    qr{added: 192.0.2.20/32,} => 1,
	    qr{added: 2001:db8::20/128,} => 1,
	},
    },
    pfctl => {
	updated => [4, 1],
	func => sub {
	    my $self = shift;
	    my $nsd = $self->{nsd};
	    my $pfresolved = $self->{pfresolved};

	    $self->show();
	    $nsd->zone(
		record_list => [
		    "foo		A	192.0.2.10",
		    "bar		AAAA	2001:DB8::10",
		    "foobar		A	192.0.2.20",
		    "foobar		AAAA	2001:DB8::20",
		],
		sighup => 1,
	    );

	    # wait until TTL has expired, pfresolvd delays another second
	    my $timeout = 3;
	    my ($updates, $deleted) = (2, 1);
	    my $table =
		qr/updated addresses for pf table .*, deleted: $deleted,/;
	    my $tomsg = $timeout ? " after $timeout seconds" : "";
	    my $upmsg = $updates ? " for $updates times" : "";
	    $pfresolved->loggrep($table, $timeout, $updates)
		or die ref($self), " no '$table' in $pfresolved->{logfile}",
		    $tomsg, $upmsg;

	    $self->show();
	},
	loggrep => {
	    qr/^   192.0.2.1$/ => 2,
	    qr/^   192.0.2.2$/ => 1,
	    qr/^   192.0.2.10$/ => 0,  # foo not updated
	    qr/^   192.0.2.20$/ => 1,  # foobar updated after ttl expired
	    qr/^   2001:db8::1$/ => 2,
	    qr/^   2001:db8::2$/ => 1,
	    qr/^   2001:db8::10$/ => 0,  # bar not updated
	    qr/^   2001:db8::20$/ => 1,  # foobar updated after ttl expired
	},
    },
);

1;
