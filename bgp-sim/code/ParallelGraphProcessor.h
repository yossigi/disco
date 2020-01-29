#ifndef __PARALLEL_GRAPH_PROCESSOR_H__
#define __PARALLEL_GRAPH_PROCESSOR_H__

#include "GraphProcessor.h"

class ParallelGraphProcessor : public GraphProcessor {
  public:
	  ParallelGraphProcessor(const BGPGraph& graph, AS::RIR attackers_region, AS::RIR victims_region, int num_cores, bool filter_two_neighbours, Log& log) : GraphProcessor(graph, attackers_region, victims_region, filter_two_neighbours), num_cores_(num_cores), log_(log) {
		cleanup();
	}
    void Process(const vector<ASPair>& ASes, unsigned int max, unsigned int hops, bool process_invert, bool length_capping, bool first_legacy);

  private:
	virtual void sumup(unsigned int hops) const;
	void compute_distribution(int filtering_mode, PATH_TYPE type, vector<double>& avg_vec, vector<double>& sd_vec, double* t_avg, double* t_sd) const;
	static void compute_distribution(const list<double>& l, double* avg, double* sd);
	void compute_path_diffs(vector<double>& avg_vec, vector<double>& sd_vec, double* avg, double* sd) const;

	void cleanup() const;

	static const int kNumGroups = 10;

	const int num_cores_;
	Log& log_;
};

#endif
