#include "RoutingTable.h"

#include <algorithm>
#include <stdexcept>

SortedASVector* RoutingTable::kSortedAses(nullptr);

RoutingTable::RoutingTable(int as_number, const BGPGraph& graph, bool filter_by_length, bool filter_two_neighbours, bool is_real_dst) :
		as_number_(as_number), graph_(graph), filter_by_length_(filter_by_length),
		my_percentile_(kSortedAses->get_as_rank_group(as_number_)), filter_(graph_, kSortedAses, filter_by_length, filter_two_neighbours) {

	if (is_real_dst) {
		list<int> self_route;
		self_route.push_back(as_number_);
		shared_ptr<Route> my_self_route(new Route(BGPGraph::LINK_NONE, self_route, Route::LEGITIMATE));
		my_self_route->optattr_protected = true;
		routing_table_.insert(pair<int, vector<shared_ptr<Route> > >(
				as_number, vector<shared_ptr<Route> >(3, my_self_route)));
	}
}

void RoutingTable::announce_spoofed_route(Route* spoofed_route) {
	shared_ptr<Route> my_spoofed_route(spoofed_route);
	routing_table_.insert(pair<int, vector<shared_ptr<Route> > >
		(spoofed_route->getDestAS(), vector<shared_ptr<Route> >(3, my_spoofed_route)));
}

bool RoutingTable::consider_new_route(Route& new_route, BGPGraph::Link_Type link_type) {
	int dst_as = new_route.getDestAS();

	update_legitimate_route_table(dst_as, new_route);

	// Discard routes with the BGP opt attribute
	if (((graph_.get(as_number_))->optattr_discard_prefix()) && new_route.optattr_protected) {
		//cout << "Discarding prefix due to optattr.\n";
		return false;
	}

	// TODO RouteFilter logic here...
	if (filter_.should_filter(as_number_, new_route, my_percentile_)) {
		return true;
	}

	shared_ptr<Route> appended_route(new Route(new_route));
//	cout << "consider_new_route appended_route->optattr_protected " << appended_route->optattr_protected << "\n";
	appended_route->append(as_number_, link_type, graph_);

	// store this route as an alternative from the neighbor,
	// we might use is later if we receive a better route that is later withdrawn
	map<int, shared_ptr<Route>> &neigh2route = alt_routes_[dst_as];
	neigh2route[appended_route->getNeighbor()] = appended_route;

	bool ret = false;
	for (int i = 0; i < 3; i++) {

		if ((link_type == BGPGraph::LINK_TO_PROVIDER) && (i > 0)) {
			break;
		}

		if ((link_type == BGPGraph::LINK_TO_PEER) && (i > 0)) {
			break;
		}

		Route* existing_route = get_route_or_null(dst_as, static_cast<ADVERTISEMENT_DEST>(i));

		map<int, vector<shared_ptr<Route> > >::iterator it = routing_table_.find(dst_as);
		if (existing_route == nullptr) {
			if (it == routing_table_.end()) {
				routing_table_.insert(pair<int, vector<shared_ptr<Route> > >
					(dst_as, vector<shared_ptr<Route> >(3, shared_ptr<Route>(nullptr))));
			}

			it = routing_table_.find(dst_as);
			it->second[i] = appended_route;
			ret = true;
		} else if (existing_route->is_new_route_better(*appended_route)) {
			it->second[i] = appended_route;
			ret = true;
		} else if (!(*existing_route == *appended_route) &&
				existing_route->from_same_neighbor(*appended_route)) {
			// Old route no longer exists as it's been overwritten
			it->second[i] = appended_route;

			int neighbor = appended_route->getNeighbor();

			// maybe one of the neighbors has offered a better route
			map<int, shared_ptr<Route>> &neigh2route = alt_routes_[dst_as];
			for(auto p : neigh2route) {
				int altneighbor = p.first;
				if(altneighbor == neighbor) { continue; }
				shared_ptr<Route> altroute = p.second;
				if(it->second[i]->is_new_route_better(*altroute)) {
					it->second[i] = altroute;
				}
			}
			ret = true;
		}
	}
	return ret;
}

Route* RoutingTable::get_my_route_or_null(int dst_as_number) const {
	Route* best = nullptr;
	for (int i = 0; i < 3; i++) {
		Route* next = get_route_or_null(dst_as_number, static_cast<ADVERTISEMENT_DEST>(i));
		if (next == nullptr) {
			continue;
		}

		if ((best == nullptr) || (best->is_new_route_better(*next))) {
			best = next;
		}
	}
	return best;
}

void RoutingTable::update_legitimate_route_table(int dst_as_number, Route& route) {
	if (!route.malicious()) {
		heard_legitimate_path_.insert(pair<int,bool>(dst_as_number, true));
	}
}

bool RoutingTable::received_only_malicious(int dst_as_number) const {
	if (heard_legitimate_path_.find(dst_as_number) == heard_legitimate_path_.cend()) return true;
	return !heard_legitimate_path_.at(dst_as_number);
}

Route* RoutingTable::get_route_or_null(int dst_as_number, ADVERTISEMENT_DEST neighbour) const {
	map<int, vector<shared_ptr<Route> > >::const_iterator i =
			routing_table_.find(dst_as_number);
	if (i == routing_table_.end()) {
		return nullptr;
	}
	return i->second[neighbour].get();
}
