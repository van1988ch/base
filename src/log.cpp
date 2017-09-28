/*
 * log.cpp
 *
 *  Created on: 2017��6��12��
 *      Author: fanzhenjun
 */

#include "log.h"
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>

namespace toy {
static Logger logger;

int log_open(FILE *fp, int level, bool is_threadsafe){
	return logger.Open(fp, level, is_threadsafe);
}

int log_open(const char *filename, int level, bool is_threadsafe, uint64_t rotate_size){
	return logger.Open(filename, level, is_threadsafe, rotate_size);
}

int log_level(){
	return logger.get_level();
}

void set_log_level(int level){
	logger.set_level(level);
}

void set_log_level(const char *s){
	std::string ss(s);
	std::transform(ss.begin(), ss.end(), ss.begin(), ::tolower);
	int level = Logger::LEVEL_DEBUG;
	if(ss == "fatal"){
		level = Logger::LEVEL_FATAL;
	}else if(ss == "error"){
		level = Logger::LEVEL_ERROR;
	}else if(ss == "warn"){
		level = Logger::LEVEL_WARN;
	}else if(ss == "info"){
		level = Logger::LEVEL_INFO;
	}else if(ss == "debug"){
		level = Logger::LEVEL_DEBUG;
	}else if(ss == "trace"){
		level = Logger::LEVEL_TRACE;
	}
	logger.set_level(level);
}

int log_write(int level, const char *fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	int ret = logger.logv(level, fmt, ap);
	va_end(ap);
	return ret;
}



Logger::Logger()
{
	this->pfile = stdout;
	this->level = LEVEL_DEBUG;
	mutex = NULL;

	rotate_size = 0;
	stats.cur = 0;
	stats.total = 0;
}

Logger::~Logger()
{
	if(mutex != NULL)
	{
		pthread_mutex_destroy(this->mutex);
		delete this->mutex;
	}
	this->close();
}

int Logger::Open(const std::string &filename , int level , bool is_threadsafe , uint64_t rotate_size)
{
	if(filename.size() > PATH_MAX)
	{
		fprintf(stderr , "filename is too long.maxlen:%d" , PATH_MAX);
		return -1;
	}

	this->level = level;
	this->filename = filename;
	this->rotate_size = rotate_size;

	FILE *fp;
	if(filename == "stdout")
		fp = stdout;
	else if(filename == "stderr")
		fp = stderr;
	else
	{
		fp = fopen(filename.c_str() , "a");
		if(fp == NULL)
		{
			fprintf(stderr , "open %s failed." , filename.c_str());
			return -1;
		}

		struct stat st;
		int ret = fstat(fileno(fp), &st);
		if(ret == -1)
		{
			fprintf(stderr , "fstat log file %s error." , filename.c_str());
			return -1;
		}
		else
			stats.cur = st.st_size;
	}

	return this->Open(fp , level , is_threadsafe);
}

int Logger::Open(FILE *pfile , int level , bool is_threadsafe)
{
	this->pfile = pfile;
	this->level = level;
	if(is_threadsafe)
	{
		return this->threadsafe();
	}
	return 0;
}

int Logger::threadsafe()
{
	if(this->mutex != NULL)
	{
		pthread_mutex_destroy(this->mutex);
		delete this->mutex;
		this->mutex = NULL;
	}

	this->mutex = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
	if(0 != pthread_mutex_init(this->mutex , NULL))
	{
		fprintf(stderr , "pthread_mutex_init error.");
		return -1;
	}
	return 0;
}

void Logger::close()
{
	if(this->pfile != stdout && this->pfile != stderr)
	{
		fclose(this->pfile);
	}
}

inline static const char* get_level_name(int level){
	switch(level){
		case Logger::LEVEL_FATAL:
			return "[FATAL] ";
		case Logger::LEVEL_ERROR:
			return "[ERROR] ";
		case Logger::LEVEL_WARN:
			return "[WARN ] ";
		case Logger::LEVEL_INFO:
			return "[INFO ] ";
		case Logger::LEVEL_DEBUG:
			return "[DEBUG] ";
		case Logger::LEVEL_TRACE:
			return "[TRACE] ";
	}
	return "";
}

const int LOG_BUF_LEN = 4096;
const int LEVEL_NAME_LEN = 8;
int Logger::logv(int level, const char *fmt, va_list ap)
{
	if(level < this->level)
		return -1;

	char buf[LOG_BUF_LEN];
	char *ptr = buf;
	int len;

	time_t time;
	struct timeval tv;
	gettimeofday(&tv , NULL);

	time = tv.tv_sec;
	struct tm *tm;
	tm = localtime(&time);

	len = sprintf(ptr, "%04d-%02d-%02d %02d:%02d:%02d.%03d ",
		tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec, (int)(tv.tv_usec/1000));

	if(len < 0){
		return -1;
	}
	ptr += len;

	memcpy(ptr, get_level_name(level), LEVEL_NAME_LEN);
	ptr += LEVEL_NAME_LEN;

	int space = sizeof(buf) - (ptr - buf) - 10;

	len = vsnprintf(ptr, space, fmt, ap);
	if(len < 0){
		return -1;
	}

	ptr += len > space? space : len;
	*ptr++ = '\n';
	*ptr = '\0';

	len = ptr - buf;

	if(this->mutex){
		pthread_mutex_lock(this->mutex);
	}

	fwrite(buf, len, 1, this->pfile);
	fflush(this->pfile);
	stats.cur += len;
	stats.total += len;

	if(rotate_size > 0 && stats.cur > rotate_size && pfile != stdout && pfile != stderr){
		this->rotate();
	}
	if(this->mutex){
		pthread_mutex_unlock(this->mutex);
	}
	return len;
}

std::string Logger::GetFileName()
{
	char newpath[PATH_MAX];
	time_t time;
	struct timeval tv;
	struct tm *tm;
	gettimeofday(&tv, NULL);
	time = tv.tv_sec;
	tm = localtime(&time);
	sprintf(newpath, "%s.%04d%02d%02d-%02d%02d%02d",
		this->filename.c_str(),
		tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
	return newpath;
}

void Logger::rotate()
{
	fclose(this->pfile);

	std::string filename = GetFileName();
	int ret = rename(this->filename.c_str(), filename.c_str());
	if(ret == -1){
		return;
	}

	this->pfile = fopen(this->filename.c_str(), "a");
	if(this->pfile == NULL){
		return;
	}
	stats.cur = 0;
}

int Logger::trace(const char *fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	int ret = logger.logv(Logger::LEVEL_TRACE, fmt, ap);
	va_end(ap);
	return ret;
}

int Logger::debug(const char *fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	int ret = logger.logv(Logger::LEVEL_DEBUG, fmt, ap);
	va_end(ap);
	return ret;
}

int Logger::info(const char *fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	int ret = logger.logv(Logger::LEVEL_INFO, fmt, ap);
	va_end(ap);
	return ret;
}

int Logger::warn(const char *fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	int ret = logger.logv(Logger::LEVEL_WARN, fmt, ap);
	va_end(ap);
	return ret;
}

int Logger::error(const char *fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	int ret = logger.logv(Logger::LEVEL_ERROR, fmt, ap);
	va_end(ap);
	return ret;
}

int Logger::fatal(const char *fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	int ret = logger.logv(Logger::LEVEL_FATAL, fmt, ap);
	va_end(ap);
	return ret;
}


} /* namespace toy */
