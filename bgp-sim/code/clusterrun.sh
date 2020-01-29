#!/bin/sh
#SBATCH -c40
#SBATCH --exclusive
#SBATCH --mem=32768
#SBATCH --time=3-0
#SBATCH --workdir=/cs/+/usr/thlavacek/sim/network_simulator-master/
./BGP.out 120 all all 1 0 100 1 false false 2 test120_c40_mem32768_20max_as.log 40 4 false false 0.01 0.005
