# test-software-routers

These scripts setup ExaBGP, BIRD, and Quagga/FRR to test how the software routers handle unassigned attributes.

## Topology

Configuration for each router is stored inside the `configs` directory:

1. `exabgp.conf`: ExaBGP instance with two sessions (one to a BIRD
   router under test and another to a Quagga router under test).

2. `bird.conf/zebra.conf/bgpd.conf`: BIRD and Quagga/FRR with two
   sessions each: one with ExaBGP (above) and another with a "client"
   running BIRD (below).

3. `birdClient.conf/quaggaClient.conf`: Two "client" instances of BIRD
   connected to the instances under test (above).

## Test

After the announcements are made, successful operation is confirmed by checking that the announcement is in the "client" instances' RIBs.

## FRR/Quagga

FRR and Quagga use the same binary names and configuration paths. This setup can be used to test one at a time (e.g., you can install Quagga packages, test, then replace Quagga with FRR and repeat the test).

## Namespaces

This setup would be improved if each software router ran in its own
namespace (instead of all routers being in a single namespace). In
particular, FRR does not accept announcements if the next hop is
assigned to one of the interfaces, so network namespace isolation is
necessary.

## Testing multiple versions

At the moment there is no automation for installing different versions
of the software routers. We tested the default version of BIRD and
Quagga on Debian Buster, Stretch, and Jessie; and two versions
of FRR (the previous release and the CVE release) on Buster.
