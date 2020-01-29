#include "GraphProcessor.h"

#include <iostream>
#include <memory>

double GraphProcessor::analyze_attacker_success_accross_rounds(
	const map<int, shared_ptr<RoutingTable> >* round1, const map<int, shared_ptr<RoutingTable> >* round2, int dst_as_number, int filtering_mode) const {
	set<int> connected_ases;
	set<int> disconnected_ases;
	// first loop, find ASes that are connected
	for (map<int, shared_ptr<RoutingTable> >::const_iterator it = round1->begin(); it != round1->end(); ++it) {
		if (!graph_.get(it->first)->is_in_region(victims_region_) && !AS::is_size_region(victims_region_)) {
			continue;
		}
		if (it->second->size() != 1) {
			continue;
		}
		Route* my_route = it->second->get_my_route_or_null(dst_as_number);
		if (my_route != nullptr) {
			connected_ases.insert(it->first);
		}
	}

	double all = 0;
	double malicious_avg_len = 0;
	double legitimate_avg_len = 0;
	// second loop find ases that got disconnected
	for (set<int>::const_iterator it = connected_ases.cbegin(); it != connected_ases.cend(); ++it) {
		all++;
		if ((round2->find(*it) == round2->cend()) || (round2->at(*it) == nullptr) || (round2->at(*it)->received_only_malicious(dst_as_number))) {
			disconnected_ases.insert(*it);
		}
	}

	if (all == 0) {
		return 0;
	}
	legitimate_avg_len /= all;
	double fooled = disconnected_ases.size();
	if (fooled != 0) {
		malicious_avg_len /= fooled;
	}

	int percentile = sorted_ases_.get_as_rank_group(dst_as_number);
	path_lengths_[filtering_mode][percentile - 1][LEGITIMATE].push_back(legitimate_avg_len);
	path_lengths_[filtering_mode][percentile - 1][MALICIOUS].push_back(malicious_avg_len);
	return (fooled / all);
}



double GraphProcessor::analyze_attacker_success(
		const map<int, shared_ptr<RoutingTable> >* attacker_results, int dst_as_number, int filtering_mode) const {
	double fooled = 0;
	double all = 0;

	double malicious_avg_len = 0;
	double legitimate_avg_len = 0;

	// iteration over ASNs, so we can select own ASNs
	for (map<int, shared_ptr<RoutingTable> >::const_iterator it = attacker_results->begin(); it != attacker_results->end(); ++it) {

		if (!graph_.get(it->first)->is_in_region(victims_region_) && !AS::is_size_region(victims_region_)) {
			//cout << "it->first.region_=" << (graph_.get(it->first)->region()) << " attackers region = " << (attackers_region_) << endl;
			//cout << "this if kills it!!" << endl;
			continue;
		}

		if (it->second->size() != 1) {
                    //cout << "this 2222222 if kills it!!" << endl;
			continue;
		}

		Route* my_route = it->second->get_my_route_or_null(dst_as_number);
		if (my_route != nullptr) {
			all++;
			if (my_route->malicious()) {
				fooled++;
				malicious_avg_len += my_route->length();

			}
			else {
				legitimate_avg_len += my_route->length();
			}
		}
	}
	if (all == 0) {
		return 0;
	}

	legitimate_avg_len /= all;

	if (fooled != 0) {
		malicious_avg_len /= fooled;
	}

	int percentile = sorted_ases_.get_as_rank_group(dst_as_number);
	path_lengths_[filtering_mode][percentile - 1][LEGITIMATE].push_back(legitimate_avg_len);
	path_lengths_[filtering_mode][percentile - 1][MALICIOUS].push_back(malicious_avg_len);

	return (fooled / all);
}

double GraphProcessor::analyze_vantage_points(
		const map<int, shared_ptr<RoutingTable> >* vantage_points, int vantage_as_number, bool skipattacker) {

	//cout << "Testing for VP: " << dst_as_number << endl;
	// iteration over ASNs, so we can select own ASNs
	map<int, shared_ptr<RoutingTable> >::const_iterator it = vantage_points->find(vantage_as_number);
	if (it != vantage_points->end()) {
		for(auto const &vprt : it->second->getRT()) {
			Route* my_route = it->second->get_my_route_or_null(vprt.first);
			if (my_route != nullptr) {
				if (skipattacker)
					noattack_vp_all_++;
				else
					vp_all_++;
				if (my_route->hijacked()) {
					if (!skipattacker) {
						vp_fooled_++;
					//	cout << "Attacker as-path length: " << my_route->length() << endl;
					}
					
				}
				if (my_route->optattr_protected) {
					if (skipattacker)
						noattack_vp_optattr_++;
					else
						vp_optattr_++;
				}
			}
		}
	}
	return 0;
}


double GraphProcessor::analyze_vantage_points_distance(
	const map<int, shared_ptr<RoutingTable> >* rt_attack, const map<int, shared_ptr<RoutingTable> >* rt_attack_only, int vantage_as_number, int victim, int attacker) {

	map<int, shared_ptr<RoutingTable> >::const_iterator it1 = rt_attack->find(vantage_as_number);
	map<int, shared_ptr<RoutingTable> >::const_iterator it2 = rt_attack_only->find(vantage_as_number);

	if ((it1 != rt_attack->end())&&(it2 != rt_attack_only->end())) {
		Route* r1 = it1->second->get_my_route_or_null(victim);
		Route* r2 = it2->second->get_my_route_or_null(attacker);

		if (r1 == NULL) {
//			cout << "Null r1 victim=" << attacker << endl;
			return 0;
		}
		if (r2 == NULL) {
//			cout << "Null r2 attacker=" << attacker << endl;
			return 0;
		}
//		cout << "Attacker as-path length: " << r2->length() << " success: " << r1->hijacked() << endl;
		if (distance_map_hijack_.find(r2->length()) == distance_map_hijack_.end())
			distance_map_hijack_[r2->length()] = (1?(r1->hijacked()==true):0);
		else
			distance_map_hijack_[r2->length()] += (1?(r1->hijacked()==true):0);

		if (distance_map_legit_.find(r2->length()) == distance_map_legit_.end())
			distance_map_legit_[r2->length()] = (0?(r1->hijacked()==true):1);
		else
			distance_map_legit_[r2->length()] += (0?(r1->hijacked()==true):1);


	} //else
//		cout << "Invalid, giving up." << endl;
	return 0;
}








double GraphProcessor::analyze_vantage_points_distance2(
	const map<int, shared_ptr<RoutingTable> >* rt_noattack, const map<int, shared_ptr<RoutingTable> >* rt_attack, const map<int, shared_ptr<RoutingTable> >* rt_attack_only, int victim, int attacker) {

	int hijack_avg_len = 0;
	int legit_avg_len = 0;
	int fooled = 0;
	int count = 0;
	int cdd = 0;

	for(int vp : graph_.vantage_points) {
		map<int, shared_ptr<RoutingTable> >::const_iterator it_attack = rt_attack->find(vp);
		map<int, shared_ptr<RoutingTable> >::const_iterator it_attack_only = rt_attack_only->find(vp);
		map<int, shared_ptr<RoutingTable> >::const_iterator it_noattack = rt_noattack->find(vp);

		if ((it_attack != rt_attack->end()) && (it_attack_only != rt_attack_only->end()) && (it_noattack != rt_noattack->end())) {
			Route* r_attack = it_attack->second->get_my_route_or_null(victim);
			Route* r_attack_only = it_attack_only->second->get_my_route_or_null(attacker);
			Route* r_noattack = it_noattack->second->get_my_route_or_null(victim);

			if ((r_attack == NULL) || (r_attack_only == NULL) || (r_noattack == NULL)) 
				continue;

			hijack_avg_len += r_attack_only->length();
			legit_avg_len += r_noattack->length();
			count++;
			cdd+= (r_noattack->length() - r_attack_only->length());

			if (r_attack->hijacked()) {
				fooled++;
		//		if (r_attack_only->length() > r_noattack->length()) {
/*					cout << "Invers on fooled attack_only=" << r_attack_only->length() << " noattack=" << r_noattack->length() << " attack=" << r_attack->length() << endl;
					cout << "attack_only aspath= ";
					for (int as: r_attack_only->get_as_list())
						cout << as << " ";
					cout << endl;
					cout << "noattack aspath= ";
					for (int as: r_noattack->get_as_list())
						cout << as << " ";
					cout << endl;
*/	
/*					hijack_avg_len += r_attack->length() - r_attack_only->length();
					legit_avg_len += r_attack->length() - r_noattack->length();
*/
		//		}
			} /*else {
				if (r_attack_only->length() < r_noattack->length())
					cout << "Invers on legit." << endl;
			} */
		}
	}

	if (count > 0)
		cout << "VP: fooled " << (((double)fooled)/count) << " hijack_avg_len " << (((double)hijack_avg_len)/count) << " legit_avg_len " << (((double)legit_avg_len)/count) << " cummulative_distance_difference " << cdd << endl;
	return 0;
}

void GraphProcessor::ProcessInternal
(const vector<ASPair>& ASPairs, int begin, int end, int max, unsigned int hops, bool proccess_invert, int* processed_count, bool filtering_mode, bool first_legacy) {

	for (int i = begin; i < end && i < max; i ++) {

            //if( i % 1000 == 0 ) cout << i << endl;
            int victim = ASPairs[i].get_victim();
            int attacker = ASPairs[i].get_attacker();
            //cout << "atttacker is: " << attacker << " victim is: " << victim << endl;
		if (victim == attacker) {
			continue;
		}

		shared_ptr< map<int, shared_ptr<RoutingTable> > > unfiltered_route_tables_1 (nullptr);
		shared_ptr< map<int, shared_ptr<RoutingTable> > > unfiltered_route_tables_2 (nullptr);

		//		for (int j = 0; j < 2; j++) {
		//		bool filtering_mode = (j != 0);
		//					if( !filtering_mode) continue;

		int j = (filtering_mode)? 1:0;
		shared_ptr< map<int, shared_ptr<RoutingTable> > > route_tables_1(Dijekstra(victim, attacker, hops, filtering_mode, first_legacy, true));
		shared_ptr< map<int, shared_ptr<RoutingTable> > > route_tables_2(Dijekstra(victim, attacker, hops, filtering_mode, first_legacy, false));
		shared_ptr< map<int, shared_ptr<RoutingTable> > > route_tables_3(Dijekstra(attacker, victim, hops, filtering_mode, first_legacy, true));

		if (j == 0) {
			unfiltered_route_tables_1 = route_tables_1;
			unfiltered_route_tables_2 = route_tables_2;
		}


		lock_.lock();
		double success_rate_j = analyze_attacker_success_accross_rounds(route_tables_1.get(), route_tables_2.get(), victim, j);
			//analyze_attacker_success(route_tables_1.get(), victim, j);
		results_[j].push_back(success_rate_j);

		/*
		if (route_tables_1 != nullptr) {
			double success_rate_j = analyze_attacker_success(route_tables_1.get(), victim, j);
			results_[j].push_back(success_rate_j);
		}

		if (route_tables_2 != nullptr) {
			double success_rate_i = analyze_attacker_success(route_tables_2.get(), attacker, j);
			results_[j].push_back(success_rate_i);
		}

		if (j == 1) {
			if ((unfiltered_route_tables_1 != nullptr) && (route_tables_1 != nullptr)) {
				count_diffs(*unfiltered_route_tables_1, *route_tables_1, victim);
			}

			if ((unfiltered_route_tables_2 != nullptr) && (route_tables_2 != nullptr)) {
				count_diffs(*unfiltered_route_tables_2, *route_tables_2, attacker);
			}
		}
		*/

		for(int vp : graph_.vantage_points) {
			analyze_vantage_points(route_tables_1.get(), vp, true); // there is no attacker
			analyze_vantage_points(route_tables_2.get(), vp, false); // there is an attacker

			//analyze_vantage_points_distance(route_tables_2.get(), route_tables_3.get(), vp, victim, attacker);
		}
		analyze_vantage_points_distance2(route_tables_1.get(), route_tables_2.get(), route_tables_3.get(), victim, attacker);

		lock_.unlock();
		//}

		lock_.lock();
		if (proccess_invert) {
			(*processed_count) += 2;
		} else {
			(*processed_count) += 1;
		}

		int local_count = *processed_count;
		lock_.unlock();

		if ((max > 0) && (local_count >= max)) {
			return;
		}
	}
}

void GraphProcessor::count_diffs(const map<int, shared_ptr<RoutingTable> >& unfiltered_routes,
		const map<int, shared_ptr<RoutingTable> >& filtered_routes, int dst_as_number) const {
	double diffs = 0;
	double all = 0;
	RouteFilter validator(graph_, &sorted_ases_, true, filter_two_neighbours_);
	for (map<int, shared_ptr<RoutingTable> >::const_iterator it = unfiltered_routes.begin();
			it != unfiltered_routes.end(); ++it) {

		if (!graph_.get(it->first)->is_in_region(victims_region_)) {
			continue;
		}

		Route* unfiltered_route = it->second->get_my_route_or_null(dst_as_number);
		if ((unfiltered_route != nullptr) && (!unfiltered_route->malicious())) {
			all++;
			Route* filtered_route = nullptr;
			if (filtered_routes.find(it->first) != filtered_routes.end()) {
				filtered_route = filtered_routes.at(it->first)->get_my_route_or_null(dst_as_number);
			}
			if ((filtered_route == nullptr) || (validator.did_adopter_lose_because_he_adopted(*unfiltered_route,*filtered_route))) {
				diffs++;
			}
		}
	}
	int percentile = sorted_ases_.get_as_rank_group(dst_as_number);
	if (all > 0) {
		path_diffs_[percentile - 1].push_back(diffs / all);
	}
	else {
		path_diffs_[percentile - 1].push_back(0);
	}
}

list<int> GraphProcessor::find_legacy_route(int dest_as_number, unsigned int min_number_of_intermidiate_ases, bool not_real_legacy) const {
	map<int, list<int>> routes_to_ases;
	queue<int> q;
	q.push(dest_as_number);
	routes_to_ases.insert(pair<int, list<int> >(dest_as_number, list<int>()));
	time_t begin_t;
	time(&begin_t);

	while (!q.empty()) {
		int curr = q.front();
		q.pop();

		time_t end_t;
		time(&end_t);
		 if( (end_t - begin_t) / 60.0 > 1 ) {
			 throw invalid_argument("find_legacy_route is taking too long!");
		 }

		if ((curr != dest_as_number) && (routes_to_ases[curr].size() >= min_number_of_intermidiate_ases)) {
			unsigned int legacy_in_a_row = 0;
			for (list<int>::const_reverse_iterator rit = routes_to_ases[curr].crbegin(); rit != routes_to_ases[curr].crend(); ++rit) {
				if (graph_.get(*rit)->legacy() || not_real_legacy) { // not_real_legacy will make the answer true even if it is not legacy
					legacy_in_a_row++;
				} else {
					break;
				}
				if (legacy_in_a_row == min_number_of_intermidiate_ases) {
					return routes_to_ases[curr];
				}
			}
		}

		for (set<int>::const_iterator neighbour = graph_.get(curr)->neighbours().cbegin();
				neighbour != graph_.get(curr)->neighbours().cend(); ++neighbour) {

			if (routes_to_ases.find(*neighbour) == routes_to_ases.end()) {
				list<int> l(routes_to_ases[curr]);
				l.push_back(*neighbour);
				routes_to_ases.insert(pair<int, list<int> >(*neighbour, l));
			} else {
				list<int> this_way(routes_to_ases[curr]);
				this_way.push_back(*neighbour);

				list<int> that_way (routes_to_ases[*neighbour]);
				if (this_way.size() < that_way.size()) {
					std::map<int, list<int> >::iterator it = routes_to_ases.find(*neighbour);
					it->second = this_way;
				}
			}
			q.push(*neighbour);
		}
	}

	throw invalid_argument("No legacy neighbour for AS.");
}

list<int> GraphProcessor::get_spoofed_route_by_hops(
		int dest_as_number, int attacker_as_number, unsigned int hops, bool first_legacy) const {
	list<int> spoofed_route;
	spoofed_route.push_back(dest_as_number);
	// if the attacker want to find the first_legacy then we need to take any AS and not just legacy

	if (hops > 0) {
		if (hops > 1) {
			list<int> intermidiate_ases(find_legacy_route(dest_as_number, hops - 1, first_legacy));
			for (list<int>::const_iterator it = intermidiate_ases.cbegin(); it != intermidiate_ases.cend(); it++) {
				spoofed_route.push_back(*it);
			}
		}
		spoofed_route.push_back(attacker_as_number);
	} 
	return spoofed_route;
}


// place of the main computation loop that works with all tables in all ASes
map<int, shared_ptr<RoutingTable> >* GraphProcessor::Dijekstra(
	int dest_as_number, int attacker_as_number, unsigned int hops, bool filter_by_length, bool first_legacy, bool skip_attacker) const {

	queue<int> q;
	map<int, shared_ptr<RoutingTable> >* route_tables = new map<int, shared_ptr<RoutingTable> >();
	set<int> in_queue;

	// insert the destination to processing queue
	route_tables->insert(pair<int, shared_ptr<RoutingTable> >
		(dest_as_number, shared_ptr<RoutingTable>(new RoutingTable(dest_as_number, graph_, filter_by_length, filter_two_neighbours_, true))));

        in_queue.insert(dest_as_number);

	// insert the attacker to processing queue
	try {
		route_tables->insert(pair<int, shared_ptr<RoutingTable> >
		(attacker_as_number, shared_ptr<RoutingTable>(new RoutingTable(attacker_as_number, graph_, filter_by_length, filter_two_neighbours_))));
		list<int> spoofed_route(get_spoofed_route_by_hops(dest_as_number, attacker_as_number, hops, first_legacy));
		Route::route_type route_type = Route::MALICIOUS;
		if (hops == 0) {
			route_type = Route::PREFIX_HIJACK;
		}
		Route* malicious_route = new Route(BGPGraph::LINK_NONE, spoofed_route, route_type);
		(*route_tables)[attacker_as_number]->announce_spoofed_route(malicious_route);
		in_queue.insert(attacker_as_number);
	} catch (const invalid_argument& ) {
		// all neighbours of dest support the protocol, hence attacker always loses (does not enter the queue).
		skip_attacker = true;
	}

	if (dest_as_number < attacker_as_number) {
		q.push(dest_as_number);
		if (!skip_attacker) {
			q.push(attacker_as_number);
		}
	} else {
		if (!skip_attacker) {
			q.push(attacker_as_number);
		}
		q.push(dest_as_number);
	}

	while (!q.empty()) {
		int current = q.front();
		const AS* currAS = graph_.get(current);
		q.pop();
		in_queue.erase(current);

		// iterate customers
		Route* optional_route = (*route_tables)[currAS->number()]->
				get_route_or_null(dest_as_number, RoutingTable::ADVERTISE_TO_CUSTOMER);

	 	bool prot_prev;
		if (optional_route != nullptr) {
	 		prot_prev = optional_route->optattr_protected;
			if (optional_route->optattr_protected && currAS->optattr_discard_attr()) {
				// cout << "Discarding the opt attribute\n";
				optional_route->optattr_protected = false;
			} // else
				//cout << "NOT Discarding the opt attribute\n";

			for (set<int>::const_iterator customer = currAS->customers().begin();
					customer != currAS->customers().end(); ++customer) {

				if ((*customer == dest_as_number) || (*customer == attacker_as_number)) {
					continue;
				}
				if (route_tables->find(*customer) == route_tables->end()) {
					route_tables->insert(pair<int, shared_ptr<RoutingTable> >
					(*customer, shared_ptr<RoutingTable>(new RoutingTable(*customer, graph_, filter_by_length, filter_two_neighbours_))));
				}
				if ((*route_tables)[*customer]->consider_new_route(*optional_route, BGPGraph::LINK_TO_PROVIDER)) {
					if (in_queue.find(*customer) == in_queue.end()) {
						q.push(*customer);
						in_queue.insert(*customer);
					}
				}
			}
			optional_route->optattr_protected = prot_prev;
		}

		// iterate peers
		optional_route = (*route_tables)[currAS->number()]->
				get_route_or_null(dest_as_number, RoutingTable::ADVERTISE_TO_PEER);

		if (optional_route != nullptr) {
			prot_prev = optional_route->optattr_protected;
			if (optional_route->optattr_protected && currAS->optattr_discard_attr()) {
				optional_route->optattr_protected = false;
				// cout << "Discarding the opt attribute\n";
			} // else
				// cout << "NOT Discarding the opt attribute\n";

			for (set<int>::const_iterator peer = currAS->peers().begin();
					peer != currAS->peers().end(); ++peer) {

					if ((*peer == dest_as_number) || (*peer == attacker_as_number)) {
					continue;
				}
				if (route_tables->find(*peer) == route_tables->end()) {
					route_tables->insert(pair<int, shared_ptr<RoutingTable> >
					(*peer, shared_ptr<RoutingTable>(new RoutingTable(*peer, graph_, filter_by_length, filter_two_neighbours_))));
				}
				if ((*route_tables)[*peer]->consider_new_route(*optional_route, BGPGraph::LINK_TO_PEER)) {
					if (in_queue.find(*peer) == in_queue.end()) {
						q.push(*peer);
						in_queue.insert(*peer);
					}
				}
			}
			optional_route->optattr_protected = prot_prev;
		}

		// iterate providers
		optional_route = (*route_tables)[currAS->number()]->
				get_route_or_null(dest_as_number, RoutingTable::ADVERTISE_TO_PROVIDER);

		if (optional_route != nullptr) {
			prot_prev = optional_route->optattr_protected;
			if (optional_route->optattr_protected && currAS->optattr_discard_attr()) {
				optional_route->optattr_protected = false;
				// cout << "Discarding the opt attribute\n";
			} // else
				// cout << "NOT Discarding the opt attribute\n";
	
			for (set<int>::const_iterator provider = currAS->providers().begin();
					provider != currAS->providers().end(); ++provider) {


				if ((*provider == dest_as_number) || (*provider == attacker_as_number)) {
					continue;
				}

				if (route_tables->find(*provider) == route_tables->end()) {
					route_tables->insert(pair<int, shared_ptr<RoutingTable> >
					(*provider, shared_ptr<RoutingTable>(new RoutingTable(*provider, graph_, filter_by_length, filter_two_neighbours_))));
				}
				if ((*route_tables)[*provider]->consider_new_route(*optional_route, BGPGraph::LINK_TO_CUSTOMER)) {
					if (in_queue.find(*provider) == in_queue.end()) {
						q.push(*provider);
						in_queue.insert(*provider);
					}
				}
			}
			optional_route->optattr_protected = prot_prev;
		}
	}

	return route_tables;
}
/*
map<int, shared_ptr<RoutingTable> >* GraphProcessor::Dijekstra_avichai(
		int dest_as_number, int attacker_as_number, unsigned int hops, bool filter_by_length) const {

	queue<int> q;
	map<int, shared_ptr<RoutingTable> >* route_tables = new map<int, shared_ptr<RoutingTable> >();
	set<int> in_queue;
	bool skip_attacker = false;

	// insert the destination to processing queue
	route_tables->insert(pair<int, shared_ptr<RoutingTable> >
	(dest_as_number, shared_ptr<RoutingTable>(new RoutingTable(dest_as_number, graph_, filter_by_length, filter_two_neighbours_, true))));
	in_queue.insert(dest_as_number);

	// insert the attacker to processing queue
	try {
		route_tables->insert(pair<int, shared_ptr<RoutingTable> >
		(attacker_as_number, shared_ptr<RoutingTable>(new RoutingTable(attacker_as_number, graph_, filter_by_length, filter_two_neighbours_))));
		list<int> spoofed_route(get_spoofed_route_by_hops(dest_as_number, attacker_as_number, hops));
		Route::route_type route_type = Route::MALICIOUS;
		if (hops == 0) {
			route_type = Route::PREFIX_HIJACK;
		}
		Route* malicious_route = new Route(BGPGraph::LINK_NONE, spoofed_route, route_type);
		(*route_tables)[attacker_as_number]->announce_spoofed_route(malicious_route);
		in_queue.insert(attacker_as_number);
	} catch (const invalid_argument& ) {
		// all neighbours of dest support the protocol, hence attacker always loses (does not enter the queue).
		skip_attacker = true;
	}

	if (dest_as_number < attacker_as_number) {
		q.push(dest_as_number);
		if (!skip_attacker) {
			q.push(attacker_as_number);
		}
	} else {
		if (!skip_attacker) {
			q.push(attacker_as_number);
		}
		q.push(dest_as_number);
	}

	Route* optional_route;
	int current;
	const AS* currAS;
	set<int> have_route;

	// iterate providers
	while (!q.empty()) {
		current = q.front();
		currAS = graph_.get(current);
		q.pop();
		in_queue.erase(current);
		have_route.insert(current);

		optional_route = (*route_tables)[currAS->number()]->
				get_route_or_null(dest_as_number, RoutingTable::ADVERTISE_TO_PROVIDER);
		if (optional_route != nullptr) {
			for (set<int>::const_iterator provider = currAS->providers().begin();
					provider != currAS->providers().end(); ++provider) {

				if ((*provider == dest_as_number) || (*provider == attacker_as_number)) {
					continue;
				}

				if (route_tables->find(*provider) == route_tables->end()) {
					route_tables->insert(pair<int, shared_ptr<RoutingTable> >
					(*provider, shared_ptr<RoutingTable>(new RoutingTable(*provider, graph_, filter_by_length, filter_two_neighbours_))));
				}
				if ((*route_tables)[*provider]->consider_new_route(*optional_route, BGPGraph::LINK_TO_CUSTOMER)) {
					if (in_queue.find(*provider) == in_queue.end()) {
						q.push(*provider);
						in_queue.insert(*provider);
					}
				}
			}
		}
	}

	// iterate peers
	// in_queue will hold the peers that we have assigned with routes. the main usage is to insert them into q only once.
	// have_route holds the victim, the attacker and all of the ASes that has route to one of them.
	for( set<int>::iterator it = have_route.begin() ; it != have_route.end() ; ++it ) {
		current = *it;
		currAS = graph_.get(current);
		q.push(current);
		in_queue.insert(current);

		optional_route = (*route_tables)[currAS->number()]->
				get_route_or_null(dest_as_number, RoutingTable::ADVERTISE_TO_PEER);
		if (optional_route != nullptr) {
			for (set<int>::const_iterator peer = currAS->peers().begin();
					peer != currAS->peers().end(); ++peer) {

				if ((*peer == dest_as_number) || (*peer == attacker_as_number)) {
					continue;
				}
				if (route_tables->find(*peer) == route_tables->end()) {
					route_tables->insert(pair<int, shared_ptr<RoutingTable> >
					(*peer, shared_ptr<RoutingTable>(new RoutingTable(*peer, graph_, filter_by_length, filter_two_neighbours_))));
				}
				if ((*route_tables)[*peer]->consider_new_route(*optional_route, BGPGraph::LINK_TO_PEER)) {
					if (in_queue.find(*peer) == in_queue.end()) {
						q.push(*peer);
						in_queue.insert(*peer);
					}
				}
			}
		}
	}


	 // in q (and in in_queue) now:
	 // 1. The victim and the attacker.
	 // 2. every AS that has customer path to the prefix.
	 // 3. every AS that has peer path to the prefix.


	// iterate costumers
	while (!q.empty()) {
		current = q.front();
		currAS = graph_.get(current);
		q.pop();
		in_queue.erase(current);

		optional_route = (*route_tables)[currAS->number()]->
				get_route_or_null(dest_as_number, RoutingTable::ADVERTISE_TO_CUSTOMER);
		if (optional_route != nullptr) {
			for (set<int>::const_iterator customer = currAS->customers().begin();
					customer != currAS->customers().end(); ++customer) {

				if ((*customer == dest_as_number) || (*customer == attacker_as_number)) {
					continue;
				}
				if (route_tables->find(*customer) == route_tables->end()) {
					route_tables->insert(pair<int, shared_ptr<RoutingTable> >
					(*customer, shared_ptr<RoutingTable>(new RoutingTable(*customer, graph_, filter_by_length, filter_two_neighbours_))));
				}
				if ((*route_tables)[*customer]->consider_new_route(*optional_route, BGPGraph::LINK_TO_PROVIDER)) {
					if (in_queue.find(*customer) == in_queue.end()) {
						q.push(*customer);
						in_queue.insert(*customer);
					}
				}
			}
		}
	}

	return route_tables;
}
 */
