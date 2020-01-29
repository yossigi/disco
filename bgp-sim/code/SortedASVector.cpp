#include "SortedASVector.h"

#include <algorithm>
#include <iostream>

map<int, shared_ptr<AS> >* SortedASVector::kPlainGraph(nullptr);

int SortedASVector::get_as_rank_group(int as_number) const {
	return percentiles_.at(as_number);
}

void SortedASVector::compute_ranks() {
	for (unsigned int i = 0; i < as_vector_.size(); i++) {

		int percentile = ((kResolution * i) / as_vector_.size()) + 1;
		if (percentile > kResolution) {
			percentile = kResolution;
		}
		percentiles_.insert(pair<int, int>(as_vector_[i], percentile));
	}
}

void SortedASVector::sort_ases() {
	switch (method_) {
	case BY_CUSTOMERS:
		sort(as_vector_.begin(), as_vector_.end(), &SortedASVector::compare_ases_by_customers);
		break;
	default:
		throw invalid_argument("unsupported sort method");
	}
}

bool SortedASVector::compare_ases_by_customers(int as_a, int as_b) {
	return compare_ases(as_a, as_b, BY_CUSTOMERS);
}

bool SortedASVector::compare_ases(int as_a, int as_b, COMPARISON_METHOD method) {
	switch (method) {
	case BY_NUMBER:
		return as_a > as_b;
	case BY_CUSTOMERS:
		return (*kPlainGraph)[as_a]->customers().size() > (*kPlainGraph)[as_b]->customers().size();
	case BY_PEERS:
		return (*kPlainGraph)[as_a]->peers().size() > (*kPlainGraph)[as_b]->peers().size();
	case BY_PROVIDERS:
		return (*kPlainGraph)[as_a]->providers().size() > (*kPlainGraph)[as_b]->providers().size();
	}
	return false;
}
