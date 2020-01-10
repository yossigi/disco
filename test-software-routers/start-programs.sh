#!/bin/bash
set -eu

PROGDIR=$(cd "$(dirname "$0")" ; pwd -P)
# shellcheck source=config.sh
. "$PROGDIR/config.sh"

if [[ "$(ip netns id $$)" != "$nsname" ]] ; then
    die "please run this inside the $nsname namespace" 1
fi

# For Jessie:
export PATH=$PATH:/usr/lib/quagga/

for prog in exabgp bird bgpd ; do
    command -v $prog >/dev/null || die "$prog not found" 1
done

bird -c configs/quaggaClient.conf -s run/quaggaClient.ctl -P run/quaggaClient.pid
bird -c configs/birdClient.conf -s run/birdClient.ctl -P run/birdClient.pid

bird -c configs/bird.conf -s run/bird.ctl -P run/bird.pid

zebra -d -f configs/zebra.conf -i /tmp/zebra.pid -z run/zebra.sock
bgpd -d -f configs/bgpd.conf -i /tmp/bgpd.pid -z run/zebra.sock -l $quaggaAddr

env exabgp.api.ack=false exabgp.log.all=TRUE exabgp.log.level=DEBUG \
        exabgp configs/exabgp.conf 2>run/exabgp.err 1>run/exabgp.out &
echo $! > run/exabgp.pid
