#ifndef __ROUTE_FILTER_H__
#define __ROUTE_FILTER_H__

#include "BGPGraph.h"
#include "Route.h"
#include "SortedASVector.h"

class RouteFilter {
public:
	RouteFilter(const BGPGraph& graph, const SortedASVector* sorted_ases, bool filter_by_length, bool two_hop_filtering_extension) :
		graph_(graph), sorted_ases_(sorted_ases), filter_by_length_(filter_by_length), two_hop_filtering_extension_(two_hop_filtering_extension) {}
	bool should_filter(int filtering_as, Route& route, int filtering_as_percentile = -1) const;
	bool did_adopter_lose_because_he_adopted(Route& unfiltered_route, Route& filtered_route) const;
private:
	const BGPGraph& graph_;
	const SortedASVector* sorted_ases_;
	const bool filter_by_length_;
	bool two_hop_filtering_extension_;
	static const int kMaxPathLength = 4;
};

#endif
