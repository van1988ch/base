/*
 * log.h
 *
 *  Created on: 2017��6��12��
 *      Author: fanzhenjun
 */

#ifndef LOG_H_
#define LOG_H_
#include <string>
#include <pthread.h>
namespace toy {


class Logger {
public:
	static const int LEVEL_NONE		= (-1);
	static const int LEVEL_MIN		= 0;
	static const int LEVEL_FATAL	= 0;
	static const int LEVEL_ERROR	= 1;
	static const int LEVEL_WARN		= 2;
	static const int LEVEL_INFO		= 3;
	static const int LEVEL_DEBUG	= 4;
	static const int LEVEL_TRACE	= 5;
	static const int LEVEL_MAX		= 5;

private:
	FILE *pfile;
	std::string filename;
	int level;
	pthread_mutex_t *mutex;
	uint64_t rotate_size;
	struct {
		uint64_t cur;
		uint64_t total;
	}stats;

public:
	Logger();
	~Logger();
	int Open(const std::string &filename , int level=LEVEL_DEBUG,
			bool is_threadsafe=false, uint64_t rotate_size=0);
	int Open(FILE *pfile , int level=LEVEL_DEBUG,bool is_threadsafe=false);
	int logv(int level, const char *fmt, va_list ap);

	int get_level(){
		return level;
	}

	void set_level(int level){
		this->level = level;
	}

	int trace(const char *fmt, ...);
	int debug(const char *fmt, ...);
	int info(const char *fmt, ...);
	int warn(const char *fmt, ...);
	int error(const char *fmt, ...);
	int fatal(const char *fmt, ...);
private:
	int threadsafe();
	void rotate();
	void close();
	std::string GetFileName();
};

int log_open(FILE *fp, int level=Logger::LEVEL_DEBUG, bool is_threadsafe=false);
int log_open(const char *filename, int level=Logger::LEVEL_DEBUG,
	bool is_threadsafe=false, uint64_t rotate_size=0);
int log_level();
void set_log_level(int level);
void set_log_level(const char *s);
int log_write(int level, const char *fmt, ...);

#ifdef NDEBUG
	#define log_trace(fmt, args...) do{}while(0)
#else
	#define log_trace(fmt, args...)	\
		log_write(toy::Logger::LEVEL_TRACE, "%s(%d): " fmt, __FILE__, __LINE__, ##args)
#endif

#define log_debug(fmt, args...)	\
	log_write(toy::Logger::LEVEL_DEBUG, "%s(%d): " fmt, __FILE__, __LINE__, ##args)
#define log_info(fmt, args...)	\
	log_write(toy::Logger::LEVEL_INFO,  "%s(%d): " fmt, __FILE__, __LINE__, ##args)
#define log_warn(fmt, args...)	\
	log_write(toy::Logger::LEVEL_WARN,  "%s(%d): " fmt, __FILE__, __LINE__, ##args)
#define log_error(fmt, args...)	\
	log_write(toy::Logger::LEVEL_ERROR, "%s(%d): " fmt, __FILE__, __LINE__, ##args)
#define log_fatal(fmt, args...)	\
	log_write(toy::Logger::LEVEL_FATAL, "%s(%d): " fmt, __FILE__, __LINE__, ##args)


} /* namespace toy */

#endif /* LOG_H_ */

