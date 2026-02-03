#include "logger.hpp"

Logger::Logger()
{
	level_map[SERVICE_START] = "INFO";
	level_map[SERVICE_STOP] = "INFO";
	level_map[CLIENT_CONNECT] = "INFO";
	level_map[CLIENT_AUTH_SUCCESS] = "INFO";
	level_map[CLIENT_AUTH_FAILURE] = "WARN";
	level_map[UPLOAD_START] = "INFO";
	level_map[UPLOAD_COMPLETE] = "INFO";
	level_map[UPLOAD_FAILURE] = "ERROR";
	level_map[UPLOAD_ABORT] = "WARN";
	level_map[DOWNLOAD_START] = "INFO";
	level_map[DOWNLOAD_COMPLETE] = "INFO";
	level_map[DOWNLOAD_FAILURE] = "ERROR";
	level_map[DOWNLOAD_ABORT] = "WARN";
	level_map[DISK_FULL] = "ERROR";
	level_map[RECOVERY_INCOMPLETE_UPLOAD] = "WARN";
}

void Logger::log_rotate()
{
	// TODO - implement this
}

void Logger::log_event(Logger::LogEvent event)
{	
	if (logfd_ < 0) return;

	const char* level = level_map[event];
	const char* event_str = event_to_string(event);

	char buf[512];
	time_t now = time(nullptr);

	int n = snprintf(
				buf,
				sizeof(buf),
				"[%ld] %s %s\n",
				now,
				level,
				event_str
			);

	if (n > 0) {
		::write(logfd_, buf, (size_t)n);
	}
}
