#!/bin/bash
set -eu

PROGDIR=$(cd "$(dirname "$0")" ; pwd -P)
# shellcheck source=config.sh
. "$PROGDIR/config.sh"

echo "enabling routing and disabling RP filter"
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv4.conf.default.rp_filter=0
sysctl -q -w net.ipv4.conf.all.rp_filter=0

echo "creating namespace $nsname"
if [ -e /var/run/netns/$nsname ] ; then
    ip netns delete $nsname
fi
ip netns add $nsname

echo "bringing up lo and setting IP addresses"
sudo ip netns exec $nsname ip link set dev lo up

# Tried to run ExaBGP on 10.1.0.1/8, but BIRD would reject the connection.
# Running ExaBGP on 10.4.0.1/8 works.  Go figure.  I am keeping the
# 10.1.0.1/8 here in case the connections were rejected based on the order
# of IPs in the interface.
sudo ip netns exec $nsname ip addr add 10.1.0.1/8 dev lo
sudo ip netns exec $nsname ip addr add $birdAddr/8 dev lo
sudo ip netns exec $nsname ip addr add $quaggaAddr/8 dev lo
sudo ip netns exec $nsname ip addr add $birdClientAddr/8 dev lo
sudo ip netns exec $nsname ip addr add $exabgpAddr/8 dev lo

echo "testing connectivity"
sudo ip netns exec $nsname ping -q -c 1 -I $exabgpAddr $birdAddr
sudo ip netns exec $nsname ping -q -c 1 -I $exabgpAddr $quaggaAddr
sudo ip netns exec $nsname ping -q -c 1 -I $birdAddr $birdClientAddr
sudo ip netns exec $nsname ping -q -c 1 -I $quaggaAddr $quaggaClientAddr
