#!/usr/bin/python3

from sys import stdout
from time import sleep
import donna25519


prefixes = ['192.168.0.0/24',]
pub_key_file = '/var/lib/disco/pub.key'
priv_key_file = '/var/lib/disco/priv.key'



def gen_keys():
    private_key = donna25519.PrivateKey()
    priv_key_bytes = private_key.private
    pub_key_bytes = private_key.get_public().public
    return priv_key_bytes, pub_key_bytes


def load_pubkey():
    with open(pub_key_file, 'rb') as fd:
        return donna25519.PublicKey(fd.read()).public


def save_keys(priv, pub):
    def save(f, k):
        with open(f, 'wb') as fd:
            fd.write(k)

    save(priv_key_file, priv)
    save(pub_key_file, pub)


def get_key_attr():
    try:
        pub_key = load_pubkey()
    except:
        priv_key, pub_key = gen_keys()
        save_keys(priv_key, pub_key)
    return hex(int.from_bytes(pub_key, byteorder='big'))


def main():
    sleep(5)
    message = 'announce route %s next-hop self attribute [0x40 0xe0 %s] \n'
    for p in prefixes:
        public_key = get_key_attr()
        stdout.write(message % (p, public_key))
        stdout.flush()
        sleep(1)

    while True:
        sleep(1) # keep running, do nothing so ExaBGP keeps running



if __name__ == '__main__':
    main()

