#include <filesystem>
#include <unordered_map>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <mutex>
#include <sys/statvfs.h>
#include <iostream>
#include "paths.hpp"

#pragma once

class Logger
{
	public:
		enum class LogLevel {
			INFO,
			WARN,
			ERROR,
		};

		enum class LogEvent {
			SERVICE_START,					// INFO
			SERVICE_STOP,					// INFO
			CLIENT_CONNECT,					// INFO
			CLIENT_AUTH_SUCCESS,			// INFO
			CLIENT_AUTH_FAILURE,			// WARN
			UPLOAD_START,					// INFO
			UPLOAD_COMPLETE,				// INFO
			UPLOAD_FAILURE,					// ERROR 
			UPLOAD_ABORT,					// WARN 
			DOWNLOAD_START,					// INFO
			DOWNLOAD_COMPLETE,				// INFO
			DOWNLOAD_FAILURE,				// ERROR
			FILE_DELETE,					// INFO
			FILE_DELETE_FAILURE,			// ERROR
			FILE_LIST,						// INFO
			FILE_LIST_FAILURE,				// ERROR
			DISK_FULL,						// ERROR 
		};
		
		std::unordered_map<LogEvent, const char*> level_map;
		
		Logger();
		
		inline const char* event_to_string(LogEvent event) {
    		switch (event) {
        		case LogEvent::SERVICE_START:  return "SERVICE_START";
        		case LogEvent::SERVICE_STOP:  return "SERVICE_STOP";
        		case LogEvent::CLIENT_CONNECT: return "CLIENT_CONNECT";
				case LogEvent::CLIENT_AUTH_SUCCESS: return "CLIENT_AUTH_SUCCESS";
				case LogEvent::CLIENT_AUTH_FAILURE: return "CLIENT_AUTH_FAILURE";
				case LogEvent::UPLOAD_START: return "UPLOAD_START";
				case LogEvent::UPLOAD_COMPLETE: return "UPLOAD_COMPLETE";
				case LogEvent::UPLOAD_FAILURE: return "UPLOAD_FAILURE";
				case LogEvent::UPLOAD_ABORT: return "UPLOAD_ABORT";
				case LogEvent::DOWNLOAD_START: return "DOWNLOAD_START";
				case LogEvent::DOWNLOAD_COMPLETE: return "DOWNLOAD_COMPLETE";
				case LogEvent::DOWNLOAD_FAILURE: return "DOWNLOAD_FAILURE";
				case LogEvent::FILE_DELETE: return "FILE_DELETE";
				case LogEvent::FILE_DELETE_FAILURE: return "FILE_DELETE_FAILURE";
				case LogEvent::FILE_LIST: return "FILE_LIST";
				case LogEvent::FILE_LIST_FAILURE: return "FILE_LIST_FAILURE";
				case LogEvent::DISK_FULL: return "DISK_FULL";
        		default:              return "UNKNOWN";
    		}
		}	

		void log_event(LogEvent event);

	private:
		std::mutex mutex;
		bool logs_enabled = true;
		
#if DEVPATHS
		inline static const std::filesystem::path log_path_{DevPaths::log_path};
#else
		inline static const std::filesystem::path log_path_{ProdPaths::log_path};
#endif

		static constexpr size_t log_max_bytes_ = 10240; // 10mb
		size_t log_cur_bytes_ = 0;
		int logfd_ = -1;
		
		struct statvfs stat;
		
		void log_rotate();
		unsigned long long get_avail_storage();
};
