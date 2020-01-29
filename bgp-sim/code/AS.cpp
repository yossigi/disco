#include "AS.h"

#include <stdexcept>
#include <iostream>


AS::AS(int as_number) : number_(as_number), region_(OTHER), state_(AS_LEGACY) { 
    /*
    if(as_number == 4761 || as_number == 29256) {
        cout << "bamba" << endl;
    }
    */
}

void AS::AddCustomer(int as_number) {
	if (is_neighbour(as_number)) { return; }
	customers_.insert(as_number);
	neighbours_.insert(as_number);
}
void AS::AddPeer(int as_number) {
	if (is_neighbour(as_number)) { return; }
	peers_.insert(as_number);
	neighbours_.insert(as_number);
}
void AS::AddProvider(int as_number) {
	if (is_neighbour(as_number)) { return; }
	providers_.insert(as_number);
	neighbours_.insert(as_number);
}

bool AS::is_neighbour(int other_as) const {
	return neighbours_.find(other_as) != neighbours_.end();
}

bool AS::is_in_region(RIR region) const {
	if (region == ALL) {
		return true;
	} else if (region == OTHER) {
		return false;
	}

	return region == region_;
}

bool AS::is_geographical_region(AS::RIR region) {
	return (region == AS::AFRINIC) || (region == AS::APNIC) || (region == AS::ARIN)
			|| (region == AS::LACNIC) || (region == AS::RIPE_NCC);
}
bool AS::is_size_region(AS::RIR region) {
    return is_categories_region(region)  || (region == AS::BIGGEST_CPS);
}

bool AS::is_categories_region(AS::RIR region) {
	return (region == AS::LARGE_ISPS) || (region == AS::MEDIUM_ISPS) ||
			(region == AS::SMALL_ISPS) || (region == AS::STUBS);
}
bool AS::is_cps_region(AS::RIR region) {
	return (region == AS::BIGGEST_CPS);
}

string AS::region_to_txt(AS::RIR region) {
	if (region == AS::AFRINIC) { return "Africa"; }
	else if (region == AS::APNIC) { return "Asia"; }
	else if (region == AS::ARIN) { return "North America"; }
	else if (region == AS::LACNIC) { return "South America"; }
	else if (region == AS::RIPE_NCC) { return "Europe"; }
	else if (region == AS::ALL) { return "All"; }
	else if (region == AS::LARGE_ISPS) { return "Large ISPs"; }
	else if (region == AS::MEDIUM_ISPS) { return "Medium ISPs"; }
	else if (region == AS::SMALL_ISPS) { return "Small ISPs"; }
	else if (region == AS::STUBS) { return "Stubs"; }
	else if (region == AS::BIGGEST_CPS) { return "BIGGEST_CPS"; }
	else { return "other"; }
}

