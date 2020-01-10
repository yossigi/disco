#!/bin/bash
set -eu

echo "showing routes from BIRD"
echo "show protocols all" | birdc -s run/birdClient.ctl
echo "show route protocol upstream all" | birdc -s run/birdClient.ctl

echo "showing routes from Quagga"
echo "show route protocol upstream all" | birdc -s run/quaggaClient.ctl
