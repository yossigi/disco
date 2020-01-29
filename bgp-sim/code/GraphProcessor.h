#ifndef __GRAPH_PROCESSOR_H__
#define __GRAPH_PROCESSOR_H__

#include "AS.h"
#include "ASList.h"
#include "RoutingTable.h"
#include "Log.h"
#include "SortedASVector.h"

#include <list>
#include <map>
#include <mutex>
#include <queue>
#include <vector>
#include <set>

using namespace std;

class GraphProcessor {
  protected:
	enum PATH_TYPE {
		LEGITIMATE = 0,
		MALICIOUS = 1
	};
GraphProcessor(const BGPGraph& graph, AS::RIR attackers_region, AS::RIR victims_region, bool filter_two_neighbours) : graph_(graph),
			all_ases_(graph.get_all_ases(AS::ALL)), sorted_ases_(all_ases_, SortedASVector::BY_CUSTOMERS, graph.get_plain()),
			attackers_region_(attackers_region), victims_region_(victims_region), filter_two_neighbours_(filter_two_neighbours) {
		RoutingTable::set_sorted_ases(&sorted_ases_);
	}

	int vp_all_ = 0;
	int noattack_vp_all_ = 0;
	int vp_fooled_ = 0;
	int noattack_vp_fooled_ = 0;
	int vp_optattr_ = 0;
	int noattack_vp_optattr_ = 0;
	mutable map<int, int> distance_map_hijack_;
	mutable map<int, int> distance_map_legit_;
	mutable list<double> results_[2];
	mutable vector< vector < list <double> > > path_lengths_[2];
	mutable vector< list <double> > path_diffs_;

	void ProcessInternal(const vector<ASPair>& ASes, int begin, int end, int max, unsigned int hops, bool proccess_invert, int* processed_count, bool filtering_mode, bool first_legacy);
  private:
	  list<int> find_legacy_route(int dest_as_number, unsigned int min_number_of_intermidiate_ases, bool real_legacy) const;
	 list<int> get_spoofed_route_by_hops(
		 int dest_as_number, int attacker_as_number, unsigned int hops, bool first_legacy) const;
	 map<int, shared_ptr<RoutingTable> >* Dijekstra(int dst_as_number, int attacker_as_number, unsigned int hops, bool filter_by_length, bool first_legacy, bool skip_attacker) const;
	 //map<int, shared_ptr<RoutingTable> >* Dijekstra_avichai(int dst_as_number, int attacker_as_number, unsigned int hops, bool filter_by_length) const;
	double analyze_attacker_success(const map<int, shared_ptr<RoutingTable> >* attacker_results, int dst_as_number, int filtering_mode) const;
	double analyze_attacker_success_accross_rounds(const map<int, shared_ptr<RoutingTable> >* attacker_results, const map<int, shared_ptr<RoutingTable> >* victim_results, int dst_as_number, int filtering_mode) const;

	double analyze_vantage_points(const map<int, shared_ptr<RoutingTable> >* vantage_points, int vantage_as_number, bool skipattacker);
	void count_diffs(const map<int, shared_ptr<RoutingTable> >& unfiltered_routes,
		 const map<int, shared_ptr<RoutingTable> >& filtered_routes, int dst_as_number) const;

	double analyze_vantage_points_distance(
		const map<int, shared_ptr<RoutingTable> >* rt_attack, const map<int, shared_ptr<RoutingTable> >* rt_attack_only, int vantage_as_number, int victim, int attacker);

	double analyze_vantage_points_distance2(
		const map<int, shared_ptr<RoutingTable> >* rt_noattack, const map<int, shared_ptr<RoutingTable> >* rt_attack, const map<int, shared_ptr<RoutingTable> >* rt_attack_only, int victim, int attacker); 


	const BGPGraph& graph_;
	mutable mutex lock_;
	vector<int> all_ases_;
	SortedASVector sorted_ases_;
	AS::RIR attackers_region_;
        AS::RIR victims_region_;
	const bool filter_two_neighbours_;
};

#endif
