#include <algorithm>
#include "RouteFilter.h"

bool RouteFilter::should_filter(int filtering_as, Route& route, int filtering_as_percentile) const {
	// Adopter AS can also validate
	if (!graph_.get(filtering_as)->adopter()) {
		return false;
	}
        
        /* 
	limit check: 3% with 100 adopters.
	if (route.malicious()) {
		return true;
	} else {
		return false;
	}
	*/

	int dst_as = route.getDestAS();

	if (filtering_as_percentile < 0) {
		filtering_as_percentile = sorted_ases_->get_as_rank_group(filtering_as);
	}

	// filter prefix hijacks
	if (route.hijacked()) { return true; }

	// Validate that first hop is valid. // TODO: change this validation to iterate the route...
	if ((route.length() > 1) && (!graph_.get(dst_as)->is_neighbour(route.getLastHop()))) {
		return true;
	}

	if (two_hop_filtering_extension_) {
		if ((route.length() > 2) && (!graph_.get(route.getLastHop())->is_neighbour(route.getBeforeLastHop()))) {
			return true;
		}
	}

	int min_percentile = std::min(sorted_ases_->get_as_rank_group(dst_as), filtering_as_percentile);
	// We force attackers to increasing path length, then enforce high limit on path length.
	if (filter_by_length_) {
		if (route.length() + 1 > 7) { //7 threshold is probably best here..
			return true;
		}
		if (graph_.are_ases_in_same_region(filtering_as, dst_as)) {
			if (filtering_as_percentile <= 5) {
				if (route.length() + 1 > 5) {
					return true;
				}
			}
			else if (filtering_as_percentile <= 15) {
				if (route.length() + 1 > 6) {
					return true;
				}
			}
		} else {
			if (min_percentile <= 3) {
				if (route.length() + 1 > 6) {
					return true;
				}
			}
		}
	}
	return false;
}

bool RouteFilter::did_adopter_lose_because_he_adopted(
		Route& unfiltered_route, Route& filtered_route) const {
	list<int> pathlet;
	list<int>::const_iterator filtering_as;
	for (filtering_as = unfiltered_route.get_as_list().cbegin();
		filtering_as != unfiltered_route.get_as_list().cend(); filtering_as++) {
		Route pathlet_route(BGPGraph::LINK_NONE, pathlet, Route::LEGITIMATE);
		if ((pathlet_route.length() > 1) && should_filter(*filtering_as, pathlet_route)) {
			break;
		}
		pathlet.push_back(*filtering_as);
	}

	if (filtering_as == unfiltered_route.get_as_list().cend()) {
		return false;
	}

	list<int>::const_iterator filtering_as_in_filtered_route;
	for (filtering_as_in_filtered_route = filtered_route.get_as_list().cbegin();
		filtering_as_in_filtered_route != filtered_route.get_as_list().cend(); filtering_as_in_filtered_route++) {
		if (*filtering_as_in_filtered_route == *filtering_as) {
			break;
		}
	}

	if (filtering_as_in_filtered_route == filtered_route.get_as_list().cend()) {
		return true;
	}

	filtering_as--;
	int unfiltered_first = *filtering_as;
	int unfiltered_second = *(filtering_as++);
	int unfiltered_third = *(filtering_as++);

	int sum_unfiltered = 
		static_cast<int>(graph_.get_link_between_ASes(unfiltered_second, unfiltered_first)) +
			static_cast<int>(graph_.get_link_between_ASes(unfiltered_second, unfiltered_third));

	filtering_as_in_filtered_route--;
	int filtered_first = *filtering_as_in_filtered_route;
	int filtered_second = *(filtering_as_in_filtered_route++);
	int filtered_third = *(filtering_as_in_filtered_route++);
	int sum_filtered =
		static_cast<int>(graph_.get_link_between_ASes(filtered_second, filtered_first)) +
		static_cast<int>(graph_.get_link_between_ASes(filtered_second, filtered_third));

	return sum_unfiltered > sum_filtered;
}
