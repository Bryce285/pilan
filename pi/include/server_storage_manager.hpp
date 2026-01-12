#include <filesystem>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <nlohmann/json.hpp>
#include <chrono>

#include "stream_writer.hpp"

#pragma once

class ServerStorageManager
{
	public:
		struct StorageConfig {
			std::filesystem::path root;
			std::filesystem::path files_dir;
			std::filesystem::path tmp_dir;
			std::filesystem::path meta_dir;

			size_t max_file_size;
			size_t max_total_size;

			bool read_only;
		};
		
		struct UploadHandle {
			int fd;

			std::filesystem::path tmp_path;
			std::filesystem::path final_path;
			std::filesystem::path meta_path;

			size_t expected_size;
			size_t bytes_written;

			EVP_MD_CTX* evp_ctx;

			bool active;
		};

		struct FileInfo {
			std::string name;
			uint64_t size_bytes;
			std::string sha256_str_hex;
			uint64_t created_at;
		};

		explicit ServerStorageManager(const StorageConfig& config);	
		
		UploadHandle start_upload(const std::string& name, size_t size);
		void write_chunk(UploadHandle& handle, const char* data, size_t len);
		void commit_upload(UploadHandle& handle);
		void abort_upload(UploadHandle& handle);

		FileInfo get_file_info(const std::string& name);
		std::vector<FileInfo> list_files();
		void delete_file(const std::string& name);
		
		void stream_file(std::string& name, StreamWriter& writer);

	private:
		StorageConfig config;
		
		std::string to_hex_string(const unsigned char* data, size_t len);
		uint64_t unix_timestamp_ms();
		std::string sanitize_filename(std::string name);
};
