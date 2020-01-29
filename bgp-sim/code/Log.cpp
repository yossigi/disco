#include "Log.h"

#ifdef WIN32
const string Log::kDir("../../../results/");
#else
const string Log::kDir("../results/");
#endif

Log::Log(const string& file) : path_(kDir + file), log_file_((path_).c_str(), std::ofstream::out | std::ofstream::app) {
	if (log_file_.fail()) {
		throw invalid_argument("Can't open log file.");
	}
}

Log::~Log() {
	log_file_.close();
}
