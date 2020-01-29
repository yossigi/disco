#include "ASList.h"

#include <time.h>

#include <iostream>

#ifdef WIN32
const string ASList::kASListFile("../../../precompute/as_list.txt");
#else
const string ASList::kASListFile("../precompute/as_list.txt");
#endif

#ifdef _DEBUG
const unsigned int ASList::kNumPairs(1100);
#else
const unsigned int ASList::kNumPairs(220000);
#endif

ASList::ASList(const BGPGraph& graph, AS::RIR attackers_region, AS::RIR victims_region, AS_SELECTION_METHOD randomize, unsigned int seed, const string& as_list_file) :
										as_list_file_(as_list_file), randomize_(randomize){

	std::random_device rd;
	std::mt19937 gen(rd());

	vector<int> attackers;

	if( attackers_region != victims_region && attackers_region == AS::ALL ) {
		vector<int> raw_attackers = graph.get_all_ases(attackers_region);
                cout << "raw_attackers' size = " << raw_attackers.size() << endl;
		for( size_t i = 0 ; i < raw_attackers.size() ; ++i ) {
			if( graph.get_as_region(raw_attackers[i]) != victims_region ) {
				attackers.push_back(raw_attackers[i]);
			}
		}
                cout << "attackers' size = " << attackers.size() << endl;
	}
	else {
		attackers = graph.get_all_ases(attackers_region);
	}

	if( attackers.size() == 0 ) {
		graph.get_size_region(attackers, attackers_region);
	}

	vector<int> victims = graph.get_all_ases(victims_region);
	cout << "victims size = " << victims.size() << endl;
        if(victims.size() == 0) {
		graph.get_size_region(victims, victims_region);
	}

	if (randomize_ == USE_CONST_ORDER) {
		gen.seed(1);
		pick_pairs(attackers, victims, gen);

		//serialize();
		return;
	}

	try {
		if (randomize_ == USE_EXISTING_RANDOM_ORDER) {
			deserialize();
			return;
		}
	}
	catch (...) {
		cout << "tried to use existing randomization, but no file. Re-randomizing." << endl;
	}
        if(seed == 0 ) {
            gen.seed(static_cast<unsigned int> (time(NULL)) );
        }
        else {
            gen.seed( seed );
        }
        pick_pairs(attackers, victims, gen);
	serialize();
	cout << "there are: " << as_pairs_.size() << " pairs" << endl;
}

const char* ASList::get_randomization_status() const {
	switch (randomize_) {
	case ASList::USE_CONST_ORDER:
		return "using constant order";
	case ASList::USE_EXISTING_RANDOM_ORDER:
		return "using existing random order";
	case ASList::RANDOMIZE:
		return "using new randomized order";
	}
	return "";
}

void ASList::pick_pairs(const vector<int>& attackers_list, const vector<int>& victims_list, mt19937& gen) {
	if ((attackers_list.size() <= 1) || (victims_list.size() <= 1)) {
		throw invalid_argument("not enough ASes");
	}

	uniform_int_distribution<> dis_attacker(0, attackers_list.size() - 1);
	uniform_int_distribution<> dis_victim(0, victims_list.size() - 1);

        //cout << endl << "attackers.size()= " << attackers_list.size() << " victims.size()= " << victims_list.size() << endl<<endl;

	unsigned int max_possible_pairs = attackers_list.size()*victims_list.size();
	if( attackers_list.size() == victims_list.size() ) {
		cout << "NOTE: number of pairs is determined assuming there are no two different regions with the same size!" << endl;
		max_possible_pairs -= victims_list.size();
	}
	if( max_possible_pairs < kNumPairs ) {
		for(size_t i = 0 ; i < attackers_list.size() ; ++i ) {
			for( size_t j = 0 ; j < victims_list.size() ; ++j ) {
				if( attackers_list[i] != victims_list[j] ) {
					as_pairs_.push_back(ASPair(victims_list[j],attackers_list[i]));
				}
			}
		}
		return;
	}
	//unsigned int number_of_pairs = (kNumPairs <= max_possible_pairs)? kNumPairs:max_possible_pairs;
	for (unsigned int i = 0; i < kNumPairs; i++) {
		//cout << "pick pairs" << i << endl;
		unsigned int attacker = attackers_list[dis_attacker(gen)];
		unsigned int victim = victims_list[dis_victim(gen)];
		while (attacker == victim) {
			victim = victims_list[dis_victim(gen)];
		}
		as_pairs_.push_back(ASPair(victim, attacker));
	}
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
	std::stringstream ss(s);
	std::string item;
	while (std::getline(ss, item, delim)) {
		elems.push_back(item);
	}
	return elems;
}


std::vector<std::string> split(const std::string &s, char delim) {
	std::vector<std::string> elems;
	split(s, delim, elems);
	return elems;
}

void ASList::deserialize() {
	ifstream raw_file(as_list_file_);
	if (raw_file.fail()) {
		throw invalid_argument("No AS List File.");
	}

	as_pairs_.clear();
	string line;
	while (!raw_file.eof()) {
		getline(raw_file, line);
		std::vector<std::string> pair = split(line, ',');
		if (line.size() > 0) {
			as_pairs_.push_back(ASPair(stoi(pair[0]), stoi(pair[1])));
		}
		if (as_pairs_.size() >= ASList::kNumPairs) {
			break;
		}
	}
}

void ASList::serialize() const {
	ofstream outfile(as_list_file_);
	if (outfile.fail()) {
		throw invalid_argument("cannot serialize AS list to file.");
	}

	for (unsigned int i = 0; i < as_pairs_.size(); i++) {
		outfile << as_pairs_[i].get_victim() << "," << as_pairs_[i].get_attacker() << endl;
	}
	outfile.close();
}
