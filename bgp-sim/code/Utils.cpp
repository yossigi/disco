#include "Utils.h"

void execute(int max_ases, unsigned int hops, AS::RIR attackers_region, AS::RIR victims_region, int deployment_low, int deployment_high,
		int jump_between_deployments, double adoption_prob, BGPGraph& graph, bool filter_two_neighbours, const ASList& as_list, const string& log_file, int num_cores,
		bool length_capping, bool first_legacy) {

	time_t now = time(nullptr);
	char date[1024];
#ifdef WIN32
	ctime_s(date, 1023, &now);
#else
	ctime_r(&now, date);
#endif
	Log log(log_file);

	cout << date << "Writing results to log file: " << log.get_path() << endl;

	if( (deployment_low != deployment_high) || (deployment_low == 0 ) ) {
		log.get() << "********************************************************************************" << endl;
		log.get() << date << "Configuration: number_ases = " << max_ases << ", hops = " << hops << ", attacker region = " << AS::region_to_txt(attackers_region) << ", victim region = " << AS::region_to_txt(victims_region);

		log.get() << ", deployment range = " << deployment_low << " -- " << deployment_high
				<< ", jump between deployments = " << jump_between_deployments << ", adoption probability = " << adoption_prob;
		log.get() << ", randomized AS pairs? = " << as_list.get_randomization_status() << ", num_cores = " << num_cores << endl;
		log.get() << "*******" << endl;
	}

	for (int i = deployment_low; i <= deployment_high; i += jump_between_deployments) {
		ParallelGraphProcessor processor(graph, attackers_region, victims_region, num_cores, filter_two_neighbours, log);
		now = time(nullptr);
#ifdef WIN32
		ctime_s(date, 1023, &now);
#else
		ctime_r(&now, date);
#endif
		log.get() << "Experiment Begins: " << date << endl;

		if( AS::is_size_region(victims_region) ) {
			graph.deploy(AS::ALL, i, adoption_prob);
		} else {
			graph.deploy(victims_region, i, adoption_prob);
		}

		log.get() << "Deployment = " << i << " ASes. [top by customers]." << endl;

		processor.Process(as_list.get(), max_ases, hops, false, length_capping, first_legacy);

		graph.clear_all_deployments();

		now = time(nullptr);
#ifdef WIN32
		ctime_s(date, 1023, &now);
#else
		ctime_r(&now, date);
#endif

		log.get() << "Experiment Ends: " << date << endl;
		log.get() << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
	}
}
