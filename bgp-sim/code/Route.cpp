#include "Route.h"

Route::Route (Route& other) : 
	last_link_(other.last_link_), as_list_(other.as_list_),
	is_malicious_(other.is_malicious_), optattr_protected(other.optattr_protected){}

bool Route::from_same_neighbor(Route& other) const {
	int this_neigh = getNeighbor();
	int other_neigh = other.getNeighbor();
	return this_neigh == other_neigh;
}

bool Route::is_new_route_better(Route& other) const {

        
	// InSecurity Second..
        // assuming adopters always filter malicious route before getting here
        // (when hops <= 1) 
     
	if (other.last_link_ < last_link_) {
		return true;
	}

	if (other.last_link_ > last_link_) {
		return false;
	}
        
	

	if (other.as_list_.size() < as_list_.size()) {
		return true;
	}

	if (other.as_list_.size() > as_list_.size()) {
		return false;
	}

	// Destination only route...
	if (as_list_.size() == 1) {
		return false;
	}

	// final break..
	list<int>::const_iterator this_val = as_list_.cend();
	list<int>::const_iterator other_val = other.as_list_.cend();
	--this_val; 
	--this_val;
	--other_val;
	--other_val;
	int x = *this_val;
	int y = *other_val;

	return x > y;
}

void Route::append(int as_number, BGPGraph::Link_Type link_type, const BGPGraph& graph) {
	as_list_.push_back(as_number);
	last_link_ = link_type;
	if (graph.get(as_number)->malicious()) {
		is_malicious_ = MALICIOUS;
	}
}

int Route::getLastHop() const {
	list<int>::const_iterator it = as_list_.cbegin();
	++it;
	return *it;
}

int Route::getBeforeLastHop() const {
	list<int>::const_iterator it = as_list_.cbegin();
	++it;
	++it;
	return *it;
}

int Route::getNeighbor() const {
	list<int>::const_iterator it = as_list_.cend();
	--it;
	--it;
	return *it;
}

 bool Route::operator==(Route& other) const {
	return as_list_ == other.as_list_;
}

 string Route::toString() const {
	ostringstream buf;
	for(auto asn : as_list_) {
		buf << asn << " ";
	}
	return buf.str();
}
