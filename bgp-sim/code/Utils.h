#ifndef __UTILS_H__
#define __UTILS_H__

#include "ParallelGraphProcessor.h"
#include "Log.h"

#include <string.h>

using namespace std;

void execute(int max_ases, unsigned int hops, AS::RIR attackers_region, AS::RIR victims_region, int deployment_low, int deployment_high,
             int jump_between_deployments, double adoption_prob, BGPGraph& graph, bool filter_two_neighbours, const ASList& as_list,
             const string& log_file, int num_cores, bool length_capping, bool first_legacy);

#endif
