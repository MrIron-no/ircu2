#! /usr/bin/perl
# IAuth stub for the hub in the integration tests.
#
# Deliberately minimal, to exercise two hub STATS paths:
#   * it sends NO "V" version line, so /STATS iauthconf reports that the
#     iauth "did not report a version";
#   * its policy omits the "S" flag, so /STATS iauth is answered
#     synchronously by ircd rather than round-tripped to us.
#
# Every client is still approved ("D") as soon as its nickname arrives, so
# registration through the hub is otherwise transparent.
use strict;
use warnings;
use FileHandle;

my %pending;   # id => { id, ip, port }

sub reply {
    my ($msg, $client) = @_;
    return unless defined $msg;
    $msg =~ s/^(.) ?/$1 $client->{id} $client->{ip} $client->{port} / if $client;
    print "$msg\n";
}

autoflush STDOUT 1;
# No "V" line on purpose.  Policy ARU: send U/P (A), wait for our verdict
# (R), send n/u/H (U).  No "S": statistics are handled synchronously.
print "O ARU\n";

while (<>) {
    s/\r?\n?\r?$//;
    my $client;
    if (s/^(-?\d+) //) {
        my $id = $1;
        $client = $pending{$id};
        if (/^C (\S+) (\S+)/) {
            $pending{$id} = { id => $id, ip => $1, port => $2 };
            next;
        }
        if (/^\? config$/) {
            print "a\n";
            print "A * iauth-tilded :policy=ARU\n";
            next;
        } elsif (/^\? stats$/) {
            print "s\n";
            next;
        }
        next unless $client;
        if (/^[DT]$/) {
            delete $pending{$id};
        } elsif (/^n (\S+)/) {
            reply("D", $client);
        }
    }
}
