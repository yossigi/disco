#ifndef __ROUTING_TABLE_H__
#define __ROUTING_TABLE_H__

#include "Route.h"
#include "AS.h"
#include "Log.h"
#include "SortedASVector.h"
#include "RouteFilter.h"

#include <map>
#include <vector>
#include <memory>

using namespace std;

class RoutingTable {
  public:
	enum ADVERTISEMENT_DEST {
		ADVERTISE_TO_CUSTOMER = 0,
		ADVERTISE_TO_PEER,
		ADVERTISE_TO_PROVIDER
	};

	RoutingTable(int as_number, const BGPGraph& graph, bool filter_by_length, bool filter_two_neighbours, bool is_real_dst = false);
	void announce_spoofed_route (Route* spoofed_route);
	bool consider_new_route(Route& new_route, BGPGraph::Link_Type link_type);
	Route* get_route_or_null(int dst_as, ADVERTISEMENT_DEST neighbour) const;
	Route* get_my_route_or_null(int dst_as_number) const;
	bool received_only_malicious(int dst_as_number) const;

	const int size() const { return routing_table_.size(); }
	const map<int, vector<shared_ptr<Route> > > getRT() const { return routing_table_; }

	static void set_sorted_ases(SortedASVector* sorted_ases) { kSortedAses = sorted_ases; }


  private:
	void update_legitimate_route_table(int dst_as_number, Route& route);

	const int as_number_;
	const BGPGraph& graph_;
	const bool filter_by_length_;
	int my_percentile_;
	const RouteFilter filter_;

	// dst as_number -> route
	map<int, vector<shared_ptr<Route> > > routing_table_;
	map<int, bool> heard_legitimate_path_;

	// dst as_number -> provider AS -> route
	map<int, map<int, shared_ptr<Route> > > alt_routes_;

	static SortedASVector* kSortedAses;
};

#endif
