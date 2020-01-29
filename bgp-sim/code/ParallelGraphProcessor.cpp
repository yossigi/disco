#include "ParallelGraphProcessor.h"

#include <math.h>
#include <thread>
#include <time.h>

void ParallelGraphProcessor::Process(const vector<ASPair>& ASPairs, unsigned int max, unsigned int hops, bool process_invert, bool length_capping, bool first_legacy) {
	time_t  begin_t;
	time(&begin_t);
	cleanup();
	shared_ptr<list<shared_ptr <thread> > > pool(new list< shared_ptr <thread> >);
	cout << "ASPairs.size=" << ASPairs.size() << endl;
	if (max > ASPairs.size()) {
		max = ASPairs.size();
	}
	cout << "max is: " << max << endl;

	int worker_size = static_cast<int>(ceil((1.0 * max) / (1.0 * num_cores_)));
	int processed_count = 0;
	for (int i = 0; i < num_cores_; i++) {
		if( size_t(i * worker_size) >= max ) { continue; }
        //cout << "thread " << i << ": " << i * worker_size << "-" << (i + 1) * worker_size << " out of " << max << endl;
		thread* worker = new thread(
				&ParallelGraphProcessor::ProcessInternal, this, ASPairs,
				i * worker_size, (i + 1) * worker_size, max, hops, process_invert, &processed_count, length_capping, first_legacy);
		pool->push_back(shared_ptr<thread>(worker));
	}

	for (list<shared_ptr <thread> >::const_iterator worker_thread = pool->begin();
			worker_thread != pool->end(); worker_thread++) {
		worker_thread->get()->join();
	}

	time_t end_t;
	time(&end_t);
	cout << "GraphProcessor::AllPairs execution time is " << (end_t - begin_t) / 60.0 << " minutes " << endl;
	log_.get() << "GraphProcessor::AllPairs execution time is " << (end_t - begin_t) / 60.0 << " minutes " << endl;
	sumup(hops);
	cleanup();
}

void ParallelGraphProcessor::cleanup() const {
	for (int i = 0; i < 2; i++) {
		path_lengths_[i].clear();
		results_[i].clear();
	}
	path_diffs_.clear();

	for (int j = 0; j < 2; j++) {
		for (int i = 0; i < SortedASVector::kResolution; i++) {
			list<double> legitimate_paths;
			list<double> malicious_paths;

			vector<list<double> > l;
			l.push_back(legitimate_paths);
			l.push_back(malicious_paths);

			path_lengths_[j].push_back(l);
		}
	}

	for (int i = 0; i < SortedASVector::kResolution; i++) {
		list<double> diffs;
		path_diffs_.push_back(diffs);
	}
}

void ParallelGraphProcessor::sumup(unsigned int hops) const {
/*	for( const auto& mp : distance_map_hijack_ ) {
		double r=((double)mp.second)/(mp.second + distance_map_legit_[mp.first]); 
		cout << "distance " << mp.first << " " << r << " (hijack=" << mp.second << " legitimate=" << distance_map_legit_[mp.first] << ")" << endl;
	} */

	for (int filtering_mode = 0; filtering_mode < 2; filtering_mode++) {
		double all = 0;
		double over_10_percent = 0;
		double sum_success_rates = 0;
		for (list<double>::const_iterator it = results_[filtering_mode].begin();
				it != results_[filtering_mode].end(); ++it) {
			all += 1;
			sum_success_rates += (*it);
			if (*it > 0.1) {
				over_10_percent += 1;
			}
		}

		double result = 0;
		if (all != 0) {
			result = over_10_percent / all;
		}

		vector<double> malicious_avg, malicious_sd, legitimate_avg, legitimate_sd;
		double t_malicious_avg, t_malicious_sd, t_legitimate_avg, t_legitimate_sd;
		compute_distribution(filtering_mode, LEGITIMATE, legitimate_avg, legitimate_sd, &t_legitimate_avg, &t_legitimate_sd);
		compute_distribution(filtering_mode, MALICIOUS, malicious_avg, malicious_sd, &t_malicious_avg, &t_malicious_sd);

		log_.get() << "Results for hops = " << hops << ", " << "filtering mode = " << filtering_mode << " case: " <<
				"There are " << 100 * result << "% attackers with over 10% success rate." << endl;
		log_.get() << "Average attacker attraction rate = " << 100 * sum_success_rates / all << "%." << endl;
		if (filtering_mode == 0) {
			log_.get() << "Vantage point routes: " << vp_all_ << endl;
			log_.get() << "Vantage point optattr: " << vp_optattr_ << endl;
			log_.get() << "Vantage point fooled: " << vp_fooled_ << endl;
			log_.get() << "Vantage point fooled percent: " << 100*(double)vp_fooled_/vp_all_ << "%" << endl;
			log_.get() << "Vantage point optattr percent: " << 100*(double)vp_optattr_/vp_all_ << "%" << endl;
		} else {
			log_.get() << "No attack Vantage point routes: " << noattack_vp_all_ << endl;
			log_.get() << "No attack Vantage point optattr: " << noattack_vp_optattr_ << endl;
			log_.get() << "No attack Vantage point fooled: " << noattack_vp_fooled_ << endl;
			log_.get() << "No attack Vantage point fooled percent: " << 100*(double)noattack_vp_fooled_/noattack_vp_all_ << "%" << endl;
			log_.get() << "No attack Vantage point optattr percent: " << 100*(double)noattack_vp_optattr_/noattack_vp_all_ << "%" << endl;
		}

		log_.get() << "Path length summary: Legitimate = " << t_legitimate_avg << "(+/-" << t_legitimate_sd << ")"
				<< "; Malicious = " << t_malicious_avg << "(+/-" << t_malicious_sd << ")" << endl;
		log_.get() << "Legitimate path length distribution: " << endl;
		for (unsigned int i = 0; i < legitimate_avg.size(); i++) {
			log_.get() << legitimate_avg[i] << "(+/-" << legitimate_sd[i] << ")\t\t\t";
		}
		log_.get() << endl;

		log_.get() << "Malicious path length distribution: " << endl;
		for (unsigned int i = 0; i < malicious_avg.size(); i++) {
			log_.get() << malicious_avg[i] << "(+/-" << malicious_sd[i] << ")\t\t\t";
		}
		log_.get() << endl;

		log_.get() << "++++++++++++" << endl;
	}
	double diffs_avg, diffs_sd;
	vector<double> t_diffs_avg, t_diffs_sd;
	compute_path_diffs(t_diffs_avg, t_diffs_sd, &diffs_avg, &diffs_sd);
	log_.get() << "Different Paths: total " << 100 * diffs_avg << "% (+/-" << 100 * diffs_sd << "%)  distribution: " << endl;
	for (unsigned int i = 0; i < t_diffs_avg.size(); i++) {
		log_.get() << 100 * t_diffs_avg[i] << "% (+/-" << 100 * t_diffs_sd[i] << "%)\t\t\t";
	}

	log_.get() << endl << "++++++++++++" << endl;
}

void ParallelGraphProcessor::compute_path_diffs(vector<double>& avg_vec, vector<double>& sd_vec, double* avg, double* sd) const {
	int size_of_group = SortedASVector::kResolution / kNumGroups;
	double all_sum = 0;
	double size_of_all = 0;

	for (int i = 0; i < kNumGroups; i++) {
		double group_sum = 0;
		double elements_in_group = 0;
		for (int j = i * size_of_group; j < (i + 1) * size_of_group; j++) {
			for (list<double>::const_iterator it = path_diffs_[j].cbegin(); it != path_diffs_[j].cend(); it++) {
				group_sum += *it;
				elements_in_group++;
			}
		}
		all_sum += group_sum;
		size_of_all += elements_in_group;
		if (elements_in_group > 0) {
			avg_vec.push_back(group_sum / elements_in_group);
		}
		else {
			avg_vec.push_back(0);
		}

	}

	*avg = 0;
	if (size_of_all > 0) {
		*avg = all_sum / size_of_all;
	}

	*sd = 0;
	for (int i = 0; i < kNumGroups; i++) {
		sd_vec.push_back(0);
		double elements_in_group = 0;
		for (int j = i * size_of_group; j < (i + 1) * size_of_group; j++) {
			for (list<double>::const_iterator it = path_diffs_[j].cbegin(); it != path_diffs_[j].cend(); it++) {
				sd_vec[i] += pow((*it - avg_vec[i]), 2);
				elements_in_group += 1;
				*sd += pow((*it - *avg), 2);
			}
		}
		if (elements_in_group != 0) {
			sd_vec[i] = sd_vec[i] / elements_in_group;
			sd_vec[i] = sqrt(sd_vec[i]);
		}
	}

	if (size_of_all > 0) {
		*sd = *sd / size_of_all;
		*sd = sqrt(*sd);
	}
}


void ParallelGraphProcessor::compute_distribution(int filtering_mode, PATH_TYPE type, vector<double>& avg_vec, vector<double>& sd_vec, double* t_avg, double* t_sd) const {
	int size_of_group = SortedASVector::kResolution / kNumGroups;
	list<double> all_list;
	vector< vector < list <double> > >& path_lengths(path_lengths_[filtering_mode]);
	for (int i = 0; i < kNumGroups; i++) {
		double avg, sd;
		list<double> legitimate_list;
		list<double> malicious_list;
		for (int j = i * size_of_group; j < (i + 1) * size_of_group; j++) {
			switch (type) {
			case LEGITIMATE:
				legitimate_list.insert(legitimate_list.end(), path_lengths[j][LEGITIMATE].begin(), path_lengths[j][LEGITIMATE].end());
				break;
			case MALICIOUS:
				malicious_list.insert(malicious_list.end(), path_lengths[j][MALICIOUS].begin(), path_lengths[j][MALICIOUS].end());
				break;
			}
		}

		switch (type) {
		case LEGITIMATE:
			compute_distribution(legitimate_list, &avg, &sd);
			all_list.insert(all_list.end(), legitimate_list.begin(), legitimate_list.end());
			break;
		case MALICIOUS:
			compute_distribution(malicious_list, &avg, &sd);
			all_list.insert(all_list.end(), malicious_list.begin(), malicious_list.end());
			break;
		}
		avg_vec.push_back(avg);
		sd_vec.push_back(sd);
	}
	compute_distribution(all_list, t_avg, t_sd);
}

void ParallelGraphProcessor::compute_distribution(const list<double>& l, double* avg, double* sd) {
	*avg = 0;
	*sd = 0;

	if (l.size() == 0) {
		return;
	}

	for (list<double>::const_iterator it = l.cbegin(); it != l.cend(); ++it) {
		*avg += *it;
	}
	*avg = (*avg) / l.size();

	for (list<double>::const_iterator it = l.cbegin(); it != l.cend(); ++it) {
		*sd += pow((*it - *avg), 2);
	}

	*sd = (*sd) / l.size();
	*sd = sqrt(*sd);
}
