#!/bin/bash

runonesim() {
	# params: prob_a prob_b logfile
	./BGP.out 150 all all 1 0 100 1 false false 2 $3 24 4 false false $1 $2
}

for a in 0.01 0.02 0.03 0.04 0.05 0.06 0.07 0.08 0.09 0.1; do
	for b in 0.01 0.02 0.03 0.04 0.05; do
		runonesim $a $b c_exp1k_${a}_${b}.log
	done
done
