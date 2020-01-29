#ifndef __BGP_GRAPH_H__
#define __BGP_GRAPH_H__

#include "AS.h"

#include <vector>
#include <memory>
#include <string>
#include <stdexcept>

class BGPGraph {
public:
	enum Link_Type {
		LINK_NONE,
		LINK_TO_CUSTOMER,
		LINK_TO_PEER,
		LINK_TO_PROVIDER
	};

	BGPGraph(bool additional_links, const string& infile = kASRelationshipsFile);

	const AS* get(int as_number) const;
	void deploy(AS::RIR region, int number_top_ases, double adoption_prob);
	vector<int> get_all_ases(AS::RIR region) const;
	void clear_all_deployments();

	map<int, shared_ptr<AS> >* get_plain() const { return graph_.get(); }

	bool are_ases_in_same_region(int as_a, int as_b) const;

	Link_Type get_link_between_ASes(int as_a, int as_b) const;

	AS::RIR get_as_region(int as_number) const;

	void set_biggest_cps();
	void get_size_region(vector<int> &ases, AS::RIR region) const;

	std::vector<int> vantage_points;

private:
	void reverse_map_regions();
	void parse_regions();
	void parse_regions(const string& input_file);
	void create_additional_links(); 
	void create_additional_caida_links();
	AS* get_mutable(int as_number) const;
	void map_as_to_region(AS::RIR region, int as_number);

	shared_ptr< map<int, shared_ptr<AS> > > graph_;

	static map<int, shared_ptr<AS> >* kPlainGraph;

	map<AS::RIR, set<int> > regions_;

	static const string kASRelationshipsFile;
	static const string kASRegionsFile;
	static const string kASRegionsFile32bit;
	static const string kASExtraRelationshipsFile;
	static const string kASExtraRelationshipsCaidaFile;
	static const string kVantagePointsFile;
	static void SplitToRelationship(
		const std::string &s, std::vector<std::string> &elems);
	static void SplitByToken(
		const std::string &s, std::vector<std::string> &elems, char token);

	bool is_customer_to_provider(int customer, int provider) const;
	bool are_peers(int peer_a, int peer_b) const;
	bool is_provider_to_customer(int provider, int customer) const;
	void set_size_regions();
	void count_ISPs();
	int read_vantage_points(const string filename);
};

#endif
