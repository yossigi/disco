#ifndef __AS_LIST_H__
#define __AS_LIST_H__

#include "AS.h"
#include "BGPGraph.h"

#include <string>
#include <fstream>
#include <istream>
#include <memory>
#include <random>
#include <stdexcept>

using namespace std;

class ASPair {
public:
	ASPair(int victim, int attacker) : victim_(victim), attacker_(attacker) {}
	int get_victim() const { return victim_; }
	int get_attacker() const { return attacker_; }
private:
	int victim_;
	int attacker_;
};

class ASList {
public:
	enum AS_SELECTION_METHOD {
		USE_CONST_ORDER,
		USE_EXISTING_RANDOM_ORDER,
		RANDOMIZE
	};
        ASList(const BGPGraph& graph, AS::RIR attackers_region, AS::RIR victims_region, AS_SELECTION_METHOD randomize, unsigned int seed = 0, const string& as_list_file = kASListFile);
	const vector<ASPair>& get() const { return as_pairs_; }
	const char* get_randomization_status() const;
private:
	void parse_as_list_from_file();
	void pick_pairs(const vector<int>& attackers_list, const vector<int>& victims_list, mt19937& gen);
	void serialize() const;
	void deserialize();

	const string& as_list_file_;
	vector<ASPair> as_pairs_;
	AS_SELECTION_METHOD randomize_;

	static const string kASListFile;
	static const unsigned int kNumPairs;
};

#endif
