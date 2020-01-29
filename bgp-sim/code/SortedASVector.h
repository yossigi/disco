#ifndef __SORTED_AS_VECTOR_H__
#define __SORTED_AS_VECTOR_H__

#include "AS.h"

#include <map>
#include <memory>
#include <stdexcept>

class SortedASVector {
public:
	enum COMPARISON_METHOD {
		BY_NUMBER,
		BY_CUSTOMERS,
		BY_PEERS,
		BY_PROVIDERS
	};

	SortedASVector(vector<int>& as_vector, COMPARISON_METHOD method, map<int, shared_ptr<AS> >* graph) : 
			as_vector_(as_vector), method_(method) { 
		kPlainGraph = graph; 
		sort_ases();
		compute_ranks();
	}

	int get_as_rank_group(int as_number) const;

	static const int kResolution = 10000;

private:
	void sort_ases();
	void compute_ranks();
	static bool compare_ases_by_customers(int as_a, int as_b);
	static bool compare_ases(int as_a, int as_b, COMPARISON_METHOD method);

	vector<int>& as_vector_;
	COMPARISON_METHOD method_;
	map<int, int> percentiles_;
	static map<int, shared_ptr<AS> >* kPlainGraph;
};

#endif
