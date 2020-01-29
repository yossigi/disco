#include "Tests.h"

#include <iostream>

bool RunAllTests(const BGPGraph& graph) {
	if (!TestRelations(graph)) {
		return false;
	}

	return true;
}

bool TestRelations(const BGPGraph& graph) {

	const list<int>& l1 = graph.get(263047)->peers();
	if (std::find(l1.begin(), l1.end(), 263061) == l1.end()) {
		cout << "error in test\n";
		return false;
	}

	const list<int>& l11 = graph.get(263061)->peers();
	if (std::find(l11.begin(), l11.end(), 263047) == l11.end()) {
		cout << "error in test\n";
		return false;
	}

	const list<int>& l2 = graph.get(263053)->customers();
	if (std::find(l2.begin(), l2.end(), 263035) == l2.end()) {
		cout << "error in test\n";
		return false;
	}


	const list<int>& l3 = graph.get(263035)->providers();
	if (std::find(l3.begin(), l3.end(), 263053) == l3.end()) {
		cout << "error in test\n";
		return false;
	}

	const list<int>& l4 = graph.get(393238)->customers();
	if (std::find(l4.begin(), l4.end(), 53616) == l4.end()) {
		cout << "error in test\n";
		return false;
	}

	const list<int>& l5 = graph.get(53616)->providers();
	if (std::find(l5.begin(), l5.end(), 393238) == l5.end()) {
		cout << "error in test\n";
		return false;
	}

	try {
		graph.get(53616111)->providers();
		cout << "error in test\n";
		return false;
	} catch (const invalid_argument&) {}

	const list<int>& l7 = graph.get(53616)->providers();
	if (std::find(l7.begin(), l7.end(), 39323811) != l7.end()) {
		cout << "error in test\n";
		return false;
	}

	cout << "All Relation Tests OK.\n";
	return true;
}

