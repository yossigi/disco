#include "AS.h" 
#include "ASList.h"
#include "ParallelGraphProcessor.h"
#include "Log.h"
#include "Utils.h"

#include <iostream>
#include <stdlib.h>
#include <string.h>

using namespace std;

double optattr_prefixdiscard_prob;
double optattr_attrdiscard_prob;

int main(int argc, char* argv[]) {
	unsigned int hops = 4;
	int max_ases = 10;
	int num_cores = 8;
	int deployment_low = 0;
	int deployment_high = 100;
	int jump_between_deployments = 10;
	double adoption_prob = 1;
	bool create_additional_links = false;
	ASList::AS_SELECTION_METHOD randomize = ASList::RANDOMIZE;
	string log_file = "test.log";
	AS::RIR attacker_region = AS::ALL;
	AS::RIR victim_region = AS::ALL;
	bool filter_two_neighbours = false;
	bool length_capping = false;
	bool first_legacy = false;

	if ((argc > 1) && string(argv[1]) == string("help")) {
		std::cout << "usage: " << argv[0] << " max_ases [" << max_ases << "] "
				<< "attacker_region [all] victim_region [all] adoption_prob [1] deployment low [" << deployment_low << "] deployment high [" << deployment_high
				<< "] jump between deployments" << "[" << jump_between_deployments << "] filter_two_neighbours [false] create_additional_links [false] randomize [" << randomize
				<< "] log_file [" << log_file << "]" <<"] num_cores [" << num_cores << "] hops [" << hops << "] length_capping [false] first_legacy [false]" << endl;
		return 0;
	}

	if (argc > 1) {
		max_ases = atoi(argv[1]);
	}

	if (argc > 2) {
		string input_attacker_region(argv[2]);
		if (input_attacker_region == "africa") { attacker_region = AS::AFRINIC; }
		else if (input_attacker_region == "asia") { attacker_region = AS::APNIC; }
		else if (input_attacker_region == "north_america") { attacker_region = AS::ARIN; }
		else if (input_attacker_region == "south_america") { attacker_region = AS::LACNIC; }
		else if (input_attacker_region == "europe") { attacker_region = AS::RIPE_NCC; }
		else if (input_attacker_region == "large") { attacker_region = AS::LARGE_ISPS; }
		else if (input_attacker_region == "medium") { attacker_region = AS::MEDIUM_ISPS; }
		else if (input_attacker_region == "small") { attacker_region = AS::SMALL_ISPS; }
		else if (input_attacker_region == "stubs") { attacker_region = AS::STUBS; }
		else if (input_attacker_region == "cps") { attacker_region = AS::BIGGEST_CPS; }
                cout << "attackers: " << input_attacker_region << " " << attacker_region << endl;
        }
	if (argc > 3) {
		string input_victim_region(argv[3]);
		if (input_victim_region == "africa") { victim_region = AS::AFRINIC; }
		else if (input_victim_region == "asia") { victim_region = AS::APNIC; }
		else if (input_victim_region == "north_america") { victim_region = AS::ARIN; }
		else if (input_victim_region == "south_america") { victim_region = AS::LACNIC; }
		else if (input_victim_region == "europe") { victim_region = AS::RIPE_NCC; }
		else if (input_victim_region == "large") { victim_region = AS::LARGE_ISPS; }
		else if (input_victim_region == "medium") { victim_region = AS::MEDIUM_ISPS; }
		else if (input_victim_region == "small") { victim_region = AS::SMALL_ISPS; }
		else if (input_victim_region == "stubs") { victim_region = AS::STUBS; }
		else if (input_victim_region == "cps") { victim_region = AS::BIGGEST_CPS; }
                cout << "victim: " << input_victim_region << " " << victim_region << endl;
        }

	//cout << "attackers region: " << region_to_txt(attacker_region) << " victims region: " << region_to_txt(victim_region) << endl;

	if (argc > 4) {
		adoption_prob = atof(argv[4]);
	}

	if (argc > 5) {
		deployment_low = atoi(argv[5]);
		deployment_high = deployment_low;
	}

	if (argc > 6) {
		deployment_high = atoi(argv[6]);
	}

	if (argc > 7) {
		jump_between_deployments = atoi(argv[7]);
		if (jump_between_deployments <= 0) {
			jump_between_deployments = 1;
		}
	}

	if (argc > 8) {
		filter_two_neighbours = (strcmp("true", argv[8]) == 0);
	}

	if (argc > 9) {
		create_additional_links = (strcmp("true", argv[9]) == 0);
	}

	if (argc > 10) {
		randomize = static_cast<ASList::AS_SELECTION_METHOD>(atoi(argv[10]));
	}

	if (argc > 11) {
		log_file = argv[11];
	}

	if (argc > 12) {
		num_cores = atoi(argv[12]);
	}

	if (argc > 13) {
		hops = atoi(argv[13]);
	}

	if (argc > 14) {
		length_capping = (strcmp("true", argv[14]) == 0);
	}

	if( argc > 15) {
		first_legacy = (strcmp("true", argv[15]) == 0);
	}

	optattr_prefixdiscard_prob = 0.01;
	optattr_attrdiscard_prob = 0.005;

	if(argc > 16) {
		sscanf(argv[16], "%lf", &optattr_prefixdiscard_prob);
	}

	if(argc > 17) {
		sscanf(argv[17], "%lf", &optattr_attrdiscard_prob);
	}

	unsigned int seed = static_cast<unsigned int> (time(NULL));
	BGPGraph graph(create_additional_links);
	ASList as_list(graph, attacker_region, victim_region, static_cast<ASList::AS_SELECTION_METHOD>(randomize),seed);
	execute(max_ases, hops, attacker_region, victim_region, deployment_low, deployment_high,
			jump_between_deployments, adoption_prob, graph, filter_two_neighbours, as_list, log_file, num_cores, length_capping, first_legacy);



//	unsigned int i = (hops==4)? 0:hops;
//	hops = (hops<4)? hops:2;
        /*
        // for lower bound
        i = 2;
        hops = 2;
        deployment_low = deployment_high = 0;
        */
/*
	for ( ; i <= hops; i++) {
		cout << "--------- hops: " << i << endl;
		BGPGraph graph(create_additional_links);
		ASList as_list(graph, attacker_region, victim_region, static_cast<ASList::AS_SELECTION_METHOD>(randomize),seed);
		execute(max_ases, i, attacker_region, victim_region, deployment_low, deployment_high,
				jump_between_deployments, adoption_prob, graph, filter_two_neighbours, as_list, log_file, num_cores, length_capping, first_legacy);
	}
*/
	cout << "done" << endl;
	time_t now = time(nullptr);
	char date[1024];
#ifdef WIN32
	ctime_s(date, 1023, &now);
#else
	ctime_r(&now, date);
#endif

	cout << "Done. Experiment Ends: " << date << endl;

	return 0;
}
