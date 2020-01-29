#ifndef __LOG_H__
#define __LOG_H__

#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>

using namespace std;

class Log {
public:
	Log(const string& file_name);
	~Log();
	const string& get_path() { return path_; }
	ofstream& get() { return log_file_; }
private:
	Log(const Log&);
	static const string kDir;
	const string path_;

	ofstream log_file_;
};

#endif
