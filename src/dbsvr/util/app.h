#ifndef UTIL_APP_H
#define UTIL_APP_H

#include <string>

class Config;

class Application{
public:
	Application(){};
	virtual ~Application(){};

	int main(const char* config_file);
	
	virtual void run() = 0;

protected:
	struct AppArgs{
		bool is_daemon;
		std::string pidfile;
		std::string conf_file;
		std::string work_dir;
		std::string start_opt;

		AppArgs(){
			is_daemon = false;
			start_opt = "start";
		}
	};

	Config *conf;
	AppArgs app_args;
	
private:
	int init();

	int read_pid();
	void write_pid();
	void check_pidfile();
	void remove_pidfile();
	void kill_process();
};

#endif
