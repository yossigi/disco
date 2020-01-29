#!/usr/bin/python3

import sys
import ipaddress
from optparse import OptionParser
from datetime import *
from mrtparse import *

attrnum = 0x40
certify_threshold = 0.95

def parse_bgp_attrs(msg, subtype):
    def get_key(attr):
        if attr.type == attrnum and attr.val:
            return '0x%s' % ''.join('%02x' % c for c in attr.val)
        else:
            return None

    def get_aspath(attr):
        if attr.type == BGP_ATTR_T['AS_PATH']:
            asp = []
            for path_seg in attr.as_path:
                asp += path_seg['val']
            return asp
        else:
            return None

    keys = []
    origins = set() 
    for attr in msg.attr:
        aspath = get_aspath(attr)
        if aspath:
            origins.add(int(aspath[-1]))

        k = get_key(attr)
        if k:
            keys.append(k)

    return (origins, keys)


def parse_bgp4mp(m, pfxkeys, pfxorigins):
    if not m.bgp.msg:
        return

    if ( m.subtype == BGP4MP_ST['BGP4MP_MESSAGE'] \
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_AS4'] \
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_LOCAL'] \
        or m.subtype == BGP4MP_ST['BGP4MP_MESSAGE_AS4_LOCAL']) \
        and m.bgp.msg.type == BGP_MSG_T['UPDATE']:
        origins, keys = parse_bgp_attrs(m.bgp.msg, m.subtype)
    else:
        return

    if m.bgp.msg.nlri:
        for n in m.bgp.msg.nlri:
            plen = n.plen - (((len(n.label) * 3 + 8) * 8) if n.label else 0)
            prefix = "%s/%d" % (n.prefix, plen)
            try:
                ipaddress.IPv4Network(prefix)
            except:
                continue

            if not prefix in pfxkeys:
                pfxkeys[prefix] = []
            pfxkeys[prefix] += keys

            if not prefix in pfxorigins:
                pfxorigins[prefix] = set()
            if origins:
                pfxorigins[prefix].update(origins)
    else:
        return


def print_acl(pfx, origins):
    for o in origins:
        print('ip as-path access-list rov permit %s le 24 %d$' % (pfx, o))
    print('ip as-path access-list rov deny %s le 32' % (pfx))


def resolve_certification(pfxkeys, pfxorigins):
    def group_count(keys):
        groups = {}
        for k in keys:
            if k in groups:
                groups[k]+=1
            else:
                groups[k]=1
        return groups

    def verify(counted_groups, total, prefix):
        for k in counted_groups:
            if counted_groups[k] > certify_threshold * total and k:
                print("Certified prefix %s with key %s (%.2f%%) for origins %s" % (prefix, k, (100*float(counted_groups[k])/total), str(pfxorigins[prefix])))
                return True
        if len(counted_groups) > 1:
            print("Warning: Prefix %s announced with multiple keys:" % p)
            for k in counted_groups:
                print("%s (%.2f)" % (k, (float(counted_groups[k])/total)))
        return False

    for p in pfxkeys:
        g = group_count(pfxkeys[p])
        v = verify(g, len(pfxkeys[p]), p)
        if v:
            print_acl(p, pfxorigins[p])


def main():
    if len(sys.argv) < 2:
        print('Usage: %s <FILENAME> [FILENAME ...]' % sys.argv[0])
        exit(1)

    pfxkeys = {}
    pfxorigins = {}

    for f in sys.argv[1:]:
        d = Reader(f)

        for m in d:
            m = m.mrt
            if m.err == MRT_ERR_C['MRT Header Error']:
                print("MRT Header Error")
                continue
            elif ( m.type == MRT_T['BGP4MP']
                or m.type == MRT_T['BGP4MP_ET']):
                parse_bgp4mp(m, pfxkeys, pfxorigins)

    resolve_certification(pfxkeys, pfxorigins)

if __name__ == '__main__':
    main()

