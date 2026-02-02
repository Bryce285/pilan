#include "logger.hpp"

Logger::Logger()
{
	level_map[SERVICE_START] = INFO;
	level_map[SERVICE_STOP] = INFO;
	level_map[CLIENT_CONNECT] = INFO;
	level_map[CLIENT_AUTH_SUCCESS] = INFO;
	level_map[CLIENT_AUTH_FAILURE] = WARN;
	level_map[UPLOAD_START] = INFO;
	level_map[UPLOAD_COMPLETE] = INFO;
	level_map[UPLOAD_FAILURE] = ERROR;
	level_map[UPLOAD_ABORT] = WARN;
	level_map[DOWNLOAD_START] = INFO;
	level_map[DOWNLOAD_COMPLETE] = INFO;
	level_map[DOWNLOAD_FAILURE] = ERROR;
	level_map[DOWNLOAD_ABORT] = WARN;
	level_map[DISK_FULL] = ERROR;
	level_map[RECOVERY_INCOMPLETE_UPLOAD] = WARN;
}

void Logger::scan_logs()
{

}

void Logger::log_rotate()
{

}

void Logger::log_event(Logger::LogEvent event, std::initializer_list<Logger::LogField> fields)
{	
	std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::chrono::system_clock::duration time_since_epoch = now.time_since_epoch();
    std::chrono::seconds seconds_since_epoch = std::chrono::duration_cast<std::chrono::seconds>(time_since_epoch);
    size_t unix_timestamp = seconds_since_epoch.count();

	LogLevel level = level_map[event];
	
	Log log {
		.timestamp = unix_timestamp;
		.level = level;
		.event = event;
		.fields = fields;
	};

	logs_buffer.push_back(log);

	if (logs_buffer.size() >= flush_threshold) {
		flush_logs();	
	}
}

bool Logger::flush_logs()
{
	
}
