#!/bin/bash

URLBASE="http://data.ris.ripe.net/rrc"

MONTH="2017.07"
TIME="20170704.2145"

for i in `seq 0 21`; do
	I=`printf "%02d\n" $i`
	n="rcc${I}-updates.${TIME}.gz"
	url="${URLBASE}${I}/${MONTH}/updates.${TIME}.gz"

	echo "$url -> $n"
	wget -O $n $url
done

