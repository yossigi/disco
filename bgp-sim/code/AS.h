#ifndef __AS_H__
#define __AS_H__

#include <list>
#include <map>
#include <vector>
#include <string>
#include <set>
#include <memory>

#include <sstream>
#include <fstream>

#define LARGE_CUSTOMERS 250
#define MEDIUM_CUSTOMERS 25

using namespace std;

class AS {
	friend class BGPGraph;
public:

	enum AS_STATE {
		AS_LEGACY,
		AS_MALICIOUS,
		AS_ADOPTER
	};

	enum AS_DISCARD_OPTATTR {
		PASS,
		DISCARD_OPTATTR,
		DISCARD_PREFIX
	};

	enum RIR {
		ALL,
		AFRINIC,
		APNIC,
		ARIN,
		LACNIC,
		RIPE_NCC,
		LARGE_ISPS,
		MEDIUM_ISPS,
		SMALL_ISPS,
		STUBS,
		BIGGEST_CPS,
		OTHER
	};

	const set<int>& customers() const {return customers_;}
	const set<int>& peers() const { return peers_; }
	const set<int>& providers() const { return providers_; }
	const set<int>& neighbours() const { return neighbours_; }
	int number() const { return number_; }
	bool is_neighbour(int other_as) const;
	bool is_in_region(RIR region) const;

	void set_state(AS_STATE new_state) { state_ = new_state; }

	bool malicious() const { return state_ == AS_MALICIOUS; }
	bool legacy() const { return state_ == AS_LEGACY; }
	bool adopter() const { return state_ == AS_ADOPTER; }

	void set_optattr_processing(AS_DISCARD_OPTATTR discard) { optattr_processing_ = discard; }
	bool optattr_discard_attr() const { return optattr_processing_ == DISCARD_OPTATTR; }
	bool optattr_discard_prefix() const { return optattr_processing_ == DISCARD_PREFIX; }

	RIR region() const { return region_; }

	static bool is_geographical_region(AS::RIR region);

	static bool is_size_region(AS::RIR region);

	static bool is_cps_region(AS::RIR resion);

	static string region_to_txt(AS::RIR region);

        static bool is_categories_region(AS::RIR region);
private:

	AS (int as_number);
	AS_DISCARD_OPTATTR optattr_processing_;

	void set_region(RIR region) { region_ = region; }

	void AddCustomer(int as_number);
	void AddPeer(int as_number);
	void AddProvider(int as_number);

	int number_;
	RIR region_;
	AS_STATE state_;
	set<int> customers_;
	set<int> peers_;
	set<int> providers_;

	set<int> neighbours_;
};

#endif
