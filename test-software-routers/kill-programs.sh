#!/bin/bash
set -eu

echo "down" | birdc -s run/quaggaClient.ctl
echo "down" | birdc -s run/birdClient.ctl

echo "down" | birdc -s run/bird.ctl

sudo pkill zebra
sudo pkill bgpd

pkill -F run/exabgp.pid
