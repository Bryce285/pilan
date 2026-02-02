#include <filesystem>

class Logger
{
	public:
		enum class LogFieldType {
    		STRING,
    		INT64,
    		UINT64,
    		BOOL
		};

		struct LogField {
    		const char* key;

    		LogFieldType type;
    		union {
        		const char* str;
        		int64_t i64;
        		uint64_t u64;
        		bool b;
    		};

    		LogField(const char* k, const char* v)
        		: key(k), type(LogFieldType::STRING), str(v) {}

    		LogField(const char* k, int64_t v)
        		: key(k), type(LogFieldType::INT64), i64(v) {}

    		LogField(const char* k, uint64_t v)
        		: key(k), type(LogFieldType::UINT64), u64(v) {}

    		LogField(const char* k, bool v)
        		: key(k), type(LogFieldType::BOOL), b(v) {}
		};

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
			DOWNLOAD_ABORT,					// WARN
			DISK_FULL,						// ERROR
			RECOVERY_INCOMPLETE_UPLOAD		// WARN
		};
		
		std::unordered_map<LogEvent, LogLevel> level_map;
		
		Logger();

		// move corrupt / incomplete logs to crash.log	
		void scan_logs();	

		// rotate logs
		bool log_rotate();

		// create a Log object and buffer in memory with logs_buffer
		void log_event(Event event, std::initializer_list<LogField> fields);

		// write logs in logs_buffer to a log file on disk
		bool flush_logs();

	private:
		std::filesystem::path logs_path = "/home/bryce/projects/offlinePiFS/pi/data/logs";
		
		// max size of an individual log file
		constexpr size_t log_size = 1024;

		// number of log files that will be created before log rotation
		constexpr size_t rotate_threshold = 10;

		constexpr size_t flush_threshold = 25;
		
		// for buffering in memory
		struct Log {
			size_t timestamp = 0;
			LogLevel level;
			LogEvent event;
			std::initializer_list<LogField> fields;
		};
		
		// for holding buffered logs
		std::vector<Log> logs_buffer;
		
		bool disk_full = false;
};
