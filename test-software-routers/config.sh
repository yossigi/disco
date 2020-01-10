# shellcheck shell=bash
# shellcheck disable=SC2148

export nsname=disco

export exabgpAddr=10.4.0.1
export exabgpASN=10000

export birdAddr=10.2.1.1
export birdASN=20001

export quaggaAddr=10.2.2.1
export quaggaASN=20002

export birdClientAddr=10.3.1.1
export birdClientASN=30001

export quaggaClientAddr=10.3.2.1
export quaggaClientASN=30002

die () {
    echo "$1"
    exit $2
}