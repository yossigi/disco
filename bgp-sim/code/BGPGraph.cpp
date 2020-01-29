#include "BGPGraph.h"

#include "SortedASVector.h"

#include <algorithm>
#include <iostream>
#include <time.h>

#ifdef WIN32
const string BGPGraph::kASRelationshipsFile("../../../data/20141201.as-rel.txt");
const string BGPGraph::kASRegionsFile("../../../data/as-geo.csv");
const string BGPGraph::kASRegionsFile32bit("../../../data/as-geo32.csv");
const string BGPGraph::kASExtraRelationshipsFile("../../../data/AS_link_extended.txt");
const string BGPGraph::kASExtraRelationshipsCaidaFile("../../../data/mlp-Dec-2014.txt");
#else
const string BGPGraph::kASRelationshipsFile("../data/20190801.as-rel.txt");
const string BGPGraph::kASRegionsFile("../data/as-numbers-1.csv");
const string BGPGraph::kASRegionsFile32bit("../data/as-numbers-2.csv");
const string BGPGraph::kASExtraRelationshipsFile("../data/AS_link_extended.txt");
const string BGPGraph::kASExtraRelationshipsCaidaFile("../data/mlp-Dec-2014.txt");
const string BGPGraph::kVantagePointsFile("../data/vantage-points-list.txt");
#endif

map<int, shared_ptr<AS> >* BGPGraph::kPlainGraph;

BGPGraph::BGPGraph(bool additional_links, const string& infile) {
	graph_.reset(new map<int, shared_ptr<AS> >());
	ifstream raw_file(infile.c_str());
	if (raw_file.fail()) {
		throw invalid_argument("No Relations File");
	}

	regions_.insert(pair<AS::RIR, set<int> >(AS::ALL, set<int>()));

	string line;
	while (!raw_file.eof()) {
		getline(raw_file, line);
		if ((line[0] != '#') && (line.length() > 0)) {
			std::vector<std::string> tokens;
			SplitToRelationship(line, tokens);
			int as_a = stoi(tokens[0]);
			int as_b = stoi(tokens[1]);
			int rel = stoi(tokens[2]);

			// allocate new ASes.
			if (graph_->find(as_a) == graph_->end()) {
				graph_->insert(pair<int, shared_ptr<AS> >(as_a, shared_ptr<AS>(new AS(as_a))));
				regions_.at(AS::ALL).insert(as_a);
			}
			if (graph_->find(as_b) == graph_->end()) {
				graph_->insert(pair<int, shared_ptr<AS> >(as_b, shared_ptr<AS>(new AS(as_b))));
				regions_.at(AS::ALL).insert(as_b);
			}

			// peers
			if (rel == 0) {
				(*graph_)[as_a]->AddPeer(as_b);
				(*graph_)[as_b]->AddPeer(as_a);
				// as_a(provider) -> as_b (customer)
			}
			else if (rel == -1) {
				(*graph_)[as_a]->AddCustomer(as_b);
				(*graph_)[as_b]->AddProvider(as_a);
			}
			else {
				throw invalid_argument("Unknown Relationship");
			}
		}
	}
	raw_file.close();
	if (additional_links) {
		create_additional_caida_links();
	}
	parse_regions();
	//set_size_regions();
	set_biggest_cps();
        /*
	for (map<AS::RIR, set<int> >::const_iterator it = regions_.cbegin(); it != regions_.cend(); it++) {
		cout << AS::region_to_txt(it->first) << " " << it->second.size() << endl;
	}
	int counter = 0;
	for (map<int, shared_ptr<AS> >::iterator it = graph_->begin(); it != graph_->end(); it++) {
		if( it->second->region() == AS::OTHER ) {
			counter++;
		}
	}
	cout << "others: " << counter << endl;
	//count_ISPs();
        */

	read_vantage_points(kVantagePointsFile);
}

void BGPGraph::count_ISPs() {
	int counter_NA = 0;
	int counter_EU = 0;
	int count_others = 0;

	for (map<int, shared_ptr<AS> >::iterator it = graph_->begin(); it != graph_->end(); it++) {
		size_t number_of_customers = it->second->customers().size();
		if( number_of_customers >= LARGE_CUSTOMERS ) {
			if( it->second->region() == AS::ARIN ) {
				counter_NA++;
			}
			else if( it->second->region() == AS::RIPE_NCC ) {
				counter_EU++;
			}
			else {
                            cout << "other region is: " << AS::region_to_txt(it->second->region()) << endl;
				count_others++;
			}
		}
	}

	cout << endl;
	cout << "Large ISPs north America: " << counter_NA << endl;
	cout << "Large ISPs Europe: " << counter_EU << endl;
	cout << "Large ISPs other: " << count_others << endl;
	cout << "total: " << count_others+counter_EU+counter_NA << endl;
	cout << endl;
}

void BGPGraph::create_additional_caida_links() {
	ifstream raw_file(kASExtraRelationshipsCaidaFile.c_str());
	if (raw_file.fail()) {
		throw invalid_argument("No Relations File");
	}

	string line;
	while (!raw_file.eof()) {
		getline(raw_file, line);
		if ((line[0] != '#') && (line.length() > 0)) {
			std::vector<std::string> tokens;
			SplitByToken(line, tokens,' ');
			int as_a = stoi(tokens[0]);
			int as_b = stoi(tokens[1]);

			// allocate new ASes.
			if (graph_->find(as_a) == graph_->end()) {
				graph_->insert(pair<int, shared_ptr<AS> >(as_a, shared_ptr<AS>(new AS(as_a))));
				regions_.at(AS::ALL).insert(as_a);
			}
			if (graph_->find(as_b) == graph_->end()) {
				graph_->insert(pair<int, shared_ptr<AS> >(as_b, shared_ptr<AS>(new AS(as_b))));
				regions_.at(AS::ALL).insert(as_b);
			}

			// peers
			(*graph_)[as_a]->AddPeer(as_b);
			(*graph_)[as_b]->AddPeer(as_a);
			// as_a(provider) -> as_b (customer)
		}
	}
	raw_file.close();
}

void BGPGraph::create_additional_links() {
	ifstream raw_file(kASExtraRelationshipsFile.c_str());
	if (raw_file.fail()) {
		throw invalid_argument("No Relations File");
	}

	string line;
	while (!raw_file.eof()) {
		getline(raw_file, line);
		if ((line[0] != '#') && (line.length() > 0)) {
			std::vector<std::string> tokens;
			SplitByToken(line, tokens, ' ');
			int as_a = stoi(tokens[0]);
			int as_b = stoi(tokens[1]);
			string rel = tokens[2];

			// allocate new ASes.
			if (graph_->find(as_a) == graph_->end()) {
				graph_->insert(pair<int, shared_ptr<AS> >(as_a, shared_ptr<AS>(new AS(as_a))));
				regions_.at(AS::ALL).insert(as_a);
			}
			if (graph_->find(as_b) == graph_->end()) {
				graph_->insert(pair<int, shared_ptr<AS> >(as_b, shared_ptr<AS>(new AS(as_b))));
				regions_.at(AS::ALL).insert(as_b);
			}

			// peers
			if (rel == "E") {
				(*graph_)[as_a]->AddPeer(as_b);
				(*graph_)[as_b]->AddPeer(as_a);
				// as_a(provider) -> as_b (customer)
			}
			else if (rel == "P") {
				(*graph_)[as_a]->AddCustomer(as_b);
				(*graph_)[as_b]->AddProvider(as_a);
			}
			else if (rel == "C") {
				(*graph_)[as_b]->AddCustomer(as_a);
				(*graph_)[as_a]->AddProvider(as_b);
			}
			else {
				continue;
			}
		}
	}
	raw_file.close();
}
extern double optattr_prefixdiscard_prob;
extern double optattr_attrdiscard_prob;

void BGPGraph::deploy(AS::RIR region, int number_top_ases, double adoption_prob) {
    
    //srand(static_cast<int>(time(NULL)));
    
      srand(1453151544);
      cout << "seed is: " << static_cast<int>(time(NULL)) << endl;
    
    //number_top_ases = static_cast<int>(ceil(number_top_ases / adoption_prob));
    kPlainGraph = graph_.get();
    vector<int> all_ases(get_all_ases(region));
    SortedASVector(all_ases, SortedASVector::BY_CUSTOMERS, kPlainGraph);
    
    int count = 0;
    for (size_t i = 0; i < all_ases.size() && count < number_top_ases ; i++) {
        /*
        if( number_top_ases == 10 ) {
            if( i < 10 ){
                continue;
            }
        }
        if( number_top_ases == 60 ) {
            if( i >= 50 && i < 60 ){
                continue;
            }
        }
        if( number_top_ases == 90 ) {
            if( i >= 80 && i < 90 ){
                continue;
            }
        }
        */
        if (static_cast<double>(rand()) / static_cast<double>(RAND_MAX) <= adoption_prob) {
            get_mutable(all_ases[i])->set_state(AS::AS_ADOPTER);
            ++count;
        }
    }

    srand(1453151544);
    for (size_t i = number_top_ases; i < all_ases.size(); i++) {
	if (static_cast<double>(rand()) / static_cast<double>(RAND_MAX) <= optattr_attrdiscard_prob*(1+optattr_prefixdiscard_prob)) {
//	   cout << "Adding AS with attrdiscard.\n";
	   get_mutable(all_ases[i])->set_optattr_processing(AS::DISCARD_OPTATTR);
	}
	
	if (static_cast<double>(rand()) / static_cast<double>(RAND_MAX) <= optattr_prefixdiscard_prob) {
	   get_mutable(all_ases[i])->set_optattr_processing(AS::DISCARD_PREFIX);
//	   cout << "Adding AS with prefixdiscard.\n";
	}
    }
    if ( count < number_top_ases ) {
        cout << "NOT ENOUGH ADOPTERS: only " << count << " out of " << number_top_ases << endl;
    }
}

void BGPGraph::clear_all_deployments() {
	vector<int> all_ases(get_all_ases(AS::ALL));
	int deployed_ases = 0;
	for (unsigned int i = 0; i < all_ases.size(); i++) {
		if (get_mutable(all_ases[i])->adopter()) {
			deployed_ases++;
		}
		get_mutable(all_ases[i])->set_state(AS::AS_LEGACY);
		get_mutable(all_ases[i])->set_optattr_processing(AS::PASS);
	}
	cout << "deployed ASes at clear: " << deployed_ases << endl;
}

void BGPGraph::SplitToRelationship(const string &s, vector<string> &elems) {

	SplitByToken(s, elems, '|');
	if (elems.size() != 3) {
		throw invalid_argument("Invalid line");
	}
}

void BGPGraph::SplitByToken(const std::string &s, std::vector<std::string> &elems, char token) {
	stringstream ss(s);
	string item;
	while (getline(ss, item, token)) {
		elems.push_back(item);
	}
}

void BGPGraph::set_biggest_cps() {
	regions_.insert(pair<AS::RIR, set<int> >(AS::BIGGEST_CPS, set<int>()));

	regions_.at(AS::BIGGEST_CPS).insert(15169); // google
	regions_.at(AS::BIGGEST_CPS).insert(22822); // limelight
	regions_.at(AS::BIGGEST_CPS).insert(20940); // akamai
	regions_.at(AS::BIGGEST_CPS).insert(8075); // microsoft
	regions_.at(AS::BIGGEST_CPS).insert(10310); // yahoo
	regions_.at(AS::BIGGEST_CPS).insert(16265); // leaseweb
	regions_.at(AS::BIGGEST_CPS).insert(15133); // edgecast
	regions_.at(AS::BIGGEST_CPS).insert(16509); // amazon
	regions_.at(AS::BIGGEST_CPS).insert(32934); // facebook
	regions_.at(AS::BIGGEST_CPS).insert(2906); // netflix
	regions_.at(AS::BIGGEST_CPS).insert(4837); // qq
	regions_.at(AS::BIGGEST_CPS).insert(13414); // twitter
	regions_.at(AS::BIGGEST_CPS).insert(40428); // pandora
	regions_.at(AS::BIGGEST_CPS).insert(14907); // wikipedia
	regions_.at(AS::BIGGEST_CPS).insert(714); // apple
	regions_.at(AS::BIGGEST_CPS).insert(23286); // hulu
	regions_.at(AS::BIGGEST_CPS).insert(38365); // baidu
}

vector<int> BGPGraph::get_all_ases(AS::RIR region) const {

	/*
	if( region != AS::ALL ) {
		parse_regions();
		set_size_regions();
	}
	 */

	vector<int> as_array;
	const set<int>* region_ases = nullptr;
	if (regions_.find(region) != regions_.cend()) {
		region_ases = &regions_.at(region);
	}

	if (region_ases == nullptr) {
		return as_array;
	}

	for (set<int>::const_iterator it = region_ases->cbegin(); it != region_ases->cend(); ++it) {
		as_array.push_back(*it);
	}

	return as_array;
}

void BGPGraph::get_size_region(vector<int>& ases, AS::RIR region) const {
	ases.clear();

	size_t min_customers = 0, max_customers = 0;

	switch(region) {
	case AS::LARGE_ISPS: {
		min_customers = LARGE_CUSTOMERS;
		max_customers = graph_->size();
		break;
	}
	case AS::MEDIUM_ISPS: {
		min_customers = MEDIUM_CUSTOMERS;
		max_customers = LARGE_CUSTOMERS;
		break;
	}
	case AS::SMALL_ISPS: {
		min_customers = 1;
		max_customers = MEDIUM_CUSTOMERS;
		break;
	}
	case AS::STUBS: {
		min_customers = 0;
		max_customers = 1;
		break;
	}
	default: return;
	}

	for (map<int, shared_ptr<AS> >::iterator it = graph_->begin(); it != graph_->end(); it++) {
		size_t customers_number = it->second->customers().size();
		if( customers_number >= min_customers && customers_number < max_customers) {
			ases.push_back(it->first);
		}
	}


}

const AS* BGPGraph::get(int as_number) const {
	return get_mutable(as_number);
}

AS* BGPGraph::get_mutable(int as_number) const {
	map<int, shared_ptr<AS> >::const_iterator i = graph_->find(as_number);
	if (i == graph_->end()) {
		throw invalid_argument("Unknown AS Number");
	}
	return i->second.get();
}

void BGPGraph::parse_regions() {
	parse_regions(kASRegionsFile);
	parse_regions(kASRegionsFile32bit);
	reverse_map_regions();
}

void BGPGraph::parse_regions(const string& input_file) {
	ifstream raw_file(input_file.c_str());
	if (raw_file.fail()) {
		throw invalid_argument("No Relations File");
	}

	string line;
	// skip the first line
	getline(raw_file, line);
	while (!raw_file.eof()) {
		getline(raw_file, line);
		if (line.length() > 0) {
			std::vector<std::string> tokens;
			SplitByToken(line, tokens, ',');
			if (tokens.size() < 2) {
				cout << "Skippihg line" << endl;
				continue;
			}
			string as_range (tokens[0]);
			string as_region(tokens[1]);
			AS::RIR region = AS::OTHER;
			if (as_region.find("ARIN") != string::npos) { region = AS::ARIN; }
			else if (as_region.find("RIPE NCC") != string::npos) { region = AS::RIPE_NCC; }
			else if (as_region.find("AFRINIC") != string::npos) { region = AS::AFRINIC; }
			else if (as_region.find("APNIC") != string::npos) { region = AS::APNIC; }
			else if (as_region.find("LACNIC") != string::npos) { region = AS::LACNIC; }
			else if (as_region.find("Unallocated") != string::npos) { continue; }

			try {
				unsigned int dash_mark = as_range.find('-');
				if (dash_mark == string::npos) {
					int as_num = stoi(as_range);
					map_as_to_region(region, as_num);
				} else {
					int low = stoi(as_range.substr(0, dash_mark));
					int high = stoi(as_range.substr(dash_mark + 1));
					for (int i = low; i <= high; i++) {
						map_as_to_region(region, i);
					}
				}
			} catch (exception& e) {}
			
		}
	}
	raw_file.close();
}

void BGPGraph::map_as_to_region(AS::RIR region, int as_number) {
	if (regions_.at(AS::ALL).find(as_number) == regions_.at(AS::ALL).end()) {
		return;
	}

	if (regions_.find(region) == regions_.end()) {
		regions_.insert(pair<AS::RIR, set<int> >(region, set<int>()));
	}

	regions_.at(region).insert(as_number);
}

AS::RIR BGPGraph::get_as_region(int as_number) const {
	for (map<AS::RIR, set<int> >::const_iterator it = regions_.cbegin(); it != regions_.cend(); it++) {
		if ((it->first != AS::ALL) && (it->first != AS::OTHER)) {
			if (it->second.find(as_number) != it->second.cend()) {
				return it->first;
			}
		}
	}
	return AS::OTHER;
}

void BGPGraph::reverse_map_regions() {
	for (map<int, shared_ptr<AS> >::iterator it = graph_->begin(); it != graph_->end(); it++) {
		it->second->set_region(get_as_region(it->first));
	}
}

bool BGPGraph::are_ases_in_same_region(int as_a, int as_b) const {
	bool same_region = (get(as_a)->region() == get(as_b)->region());
	return same_region && (get(as_a)->region() != AS::OTHER);
}

BGPGraph::Link_Type BGPGraph::get_link_between_ASes(int as_a, int as_b) const {
	if (is_customer_to_provider(as_a, as_b)) { return LINK_TO_PROVIDER; }
	else if (are_peers(as_a, as_b)) { return LINK_TO_PEER; }
	else if (is_provider_to_customer(as_a, as_b)) { return LINK_TO_CUSTOMER; }
	else { return LINK_NONE; }
}

void BGPGraph::set_size_regions() {

	regions_.insert(pair<AS::RIR, set<int> >(AS::LARGE_ISPS, set<int>()));
	regions_.insert(pair<AS::RIR, set<int> >(AS::MEDIUM_ISPS, set<int>()));
	regions_.insert(pair<AS::RIR, set<int> >(AS::SMALL_ISPS, set<int>()));
	regions_.insert(pair<AS::RIR, set<int> >(AS::STUBS, set<int>()));

	for (map<int, shared_ptr<AS> >::iterator it = graph_->begin(); it != graph_->end(); it++) {
		size_t number_of_cutomers = it->second->customers().size();
		if( number_of_cutomers >= LARGE_CUSTOMERS ) {
			regions_[AS::LARGE_ISPS].insert(it->first);
		} else if( number_of_cutomers >= MEDIUM_CUSTOMERS) {
			regions_[AS::MEDIUM_ISPS].insert(it->first);
		} else if( number_of_cutomers >= 1 ) {
			regions_[AS::SMALL_ISPS].insert(it->first);
		} else {
			regions_[AS::STUBS].insert(it->first);
		}
	}

	/*
	cout << "Large ISPs: " << regions_[AS::LARGE_ISPS].size() << endl;
	cout << "Medium ISPs: " << regions_[AS::MEDIUM_ISPS].size() << endl;
	cout << "Small ISPs: " << regions_[AS::SMALL_ISPS].size() << endl;
	cout << "Stubs: " << regions_[AS::STUBS].size() << endl;
	 */
}


bool BGPGraph::is_customer_to_provider(int customer, int provider) const {
	return (get(customer)->providers().find(provider) != get(customer)->providers().cend());
}
bool BGPGraph::are_peers(int peer_a, int peer_b) const {
	return (get(peer_a)->peers().find(peer_b) != get(peer_a)->peers().cend());;
}
bool BGPGraph::is_provider_to_customer(int provider, int customer) const {
	return (get(provider)->customers().find(customer) != get(provider)->customers().cend());
}

int BGPGraph::read_vantage_points(const string filename) {
	int vp;
	std::string l;
	ifstream fh(filename);
	if (fh.is_open()) {
		while ( getline(fh,l) ) {
			vp = stoi(l);
			if (vp>0) {
				vantage_points.push_back(vp);
			}

		}
		fh.close();
		cout << "Success reading vantage points file. Read " << vantage_points.size() << "records." << endl;
		return 0;
	} else {
		cout << "Unable to open vantage points file.";
		return -1;
	}
}
