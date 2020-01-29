#ifndef __ROUTES_H__
#define __ROUTES_H__

#include "BGPGraph.h"

#include <list>
#include <memory>

#include "Log.h"

using namespace std;

class Route {
  public:
	  enum route_type {
		  LEGITIMATE,
		  MALICIOUS,
		  PREFIX_HIJACK
	  };

	  bool optattr_protected = false;

	  Route(BGPGraph::Link_Type last_link, list<int> as_list, route_type is_malicious) :
		last_link_(last_link), as_list_(as_list), is_malicious_(is_malicious) {
		}

	Route (Route& other);

	bool is_new_route_better(Route& other) const;

	void append(int as_number, BGPGraph::Link_Type link_type, const BGPGraph& graph);

	int getDestAS() const { return as_list_.front(); }
	int getLastHop() const;
	int getBeforeLastHop() const;
	bool malicious() const { return is_malicious_ != LEGITIMATE; }
	bool hijacked() const { return is_malicious_ == PREFIX_HIJACK; }
	int length() const { return as_list_.size(); }

	const list<int>& get_as_list() const { return as_list_; }

	BGPGraph::Link_Type get_prev_link_type(int intermediate_as) const;
	bool from_same_neighbor(Route& other) const;
	int getNeighbor() const;
	bool operator==(Route& Oother) const;

 	string toString() const;
  private:

	//friend bool RouteFilter::did_adopter_lose_revenue;
	BGPGraph::Link_Type last_link_;

	// front = dst ; back = src
	list<int> as_list_;
	route_type is_malicious_;
};

#endif
