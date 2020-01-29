# DISCO PoC

## Components

* generating announcements with Ownership Token (agent)
* validating Ownership Tokens in MRT dumps from vantage points (registrar)

### Generating announcements

Prerequisite:
* ExaBGP Python API installed & set
* BGP session for ExaBGP to connect

Procedure:
* modify exabgp-example.conf to conform local BGP settings
* modify attrannounce.py to announce desired prefixes
* run ExaBGP framework:
```
$ exabgp exabgp.conf
```

### validating ownership tokens

Procedure:
* download MRT message dumps from vabtage points - helper scripts `downloadris.sh` and `downloadrouteviews.sh` can be used
* run `validate.py` for all downloaded MRT dumps

Example:
```
$ ./validate.py ../attrexperiment-201707/*.bz2
Certified prefix 188.227.157.0/24 with key 0xd204000029090000800d0000d71100002e160000851a0000d21e0000c5220000 (99.64%)
```

