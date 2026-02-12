#include "logger.hpp"

Logger::Logger()
{
	// statvfs in used to check available disk space
	// if we can't check disk space then logging is disabled
	if (statvfs("/home", &stat) != 0) {
		perror("Failed to initialize statvfs. Logging will be disabled."); 
		logs_enabled = false;
	}

	logfd_ = ::open(
        log_path_,
        O_WRONLY | O_CREAT | O_APPEND,
        0644
    );
	if (logfd_ == -1) {
		std::cerr << "Failed to open log file" << std::endl;
	}

    log_cur_bytes_ = 0;

	level_map[LogEvent::SERVICE_START] = "INFO";
	level_map[LogEvent::SERVICE_STOP] = "INFO";
	level_map[LogEvent::CLIENT_CONNECT] = "INFO";
	level_map[LogEvent::CLIENT_AUTH_SUCCESS] = "INFO";
	level_map[LogEvent::CLIENT_AUTH_FAILURE] = "WARN";
	level_map[LogEvent::UPLOAD_START] = "INFO";
	level_map[LogEvent::UPLOAD_COMPLETE] = "INFO";
	level_map[LogEvent::UPLOAD_FAILURE] = "ERROR";
	level_map[LogEvent::UPLOAD_ABORT] = "WARN";
	level_map[LogEvent::DOWNLOAD_START] = "INFO";
	level_map[LogEvent::DOWNLOAD_COMPLETE] = "INFO";
	level_map[LogEvent::DOWNLOAD_FAILURE] = "ERROR";
	level_map[LogEvent::FILE_DELETE] = "INFO";
	level_map[LogEvent::FILE_DELETE_FAILURE] = "ERROR";
	level_map[LogEvent::FILE_LIST] = "INFO";
	level_map[LogEvent::FILE_LIST_FAILURE] = "ERROR";
	level_map[LogEvent::DISK_FULL] = "ERROR";
}

unsigned long long Logger::get_avail_storage()
{
	unsigned long long available = stat.f_bavail * stat.f_frsize;
	return available;
}

void Logger::log_rotate()
{
	if (!log_path_ || log_max_bytes_ == 0) return;
    if (log_cur_bytes_ < log_max_bytes_) return;

    ::close(logfd_);

    char rotated[256];
    snprintf(rotated, sizeof(rotated), "%s.1", log_path_);

    ::rename(log_path_, rotated);

    logfd_ = ::open(
        log_path_,
        O_WRONLY | O_CREAT | O_TRUNC,
        0644
    );

    log_cur_bytes_ = 0;
}

void Logger::log_event(Logger::LogEvent event)
{
	std::lock_guard<std::mutex> lock(mutex);

	if (logs_enabled == false) return;
	if (logfd_ < 0) return;
	
	log_rotate();

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
	
	if (static_cast<unsigned long long>(n) > get_avail_storage()) return;

	if (n > 0) {
		ssize_t written = ::write(logfd_, buf, (size_t)n);
		if (written > 0) {
			log_cur_bytes_ += (size_t)written;
		}
	}
}
