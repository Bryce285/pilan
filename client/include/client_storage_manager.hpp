#include <filesystem>
#include <openssl/sha.h>
#include <fstream>
#include <iostream>

#include "stream_writer.hpp"

#pragma once

class ClientStorageManager
{
	public:
		struct StorageConfig {
			std::filesystem::path downloads_dir;
			std::filesystem::path tmp_dir;
		};

		struct DownloadHandle {
			int fd;

			std::filesystem::path tmp_path;
			std::filesystem::path final_path;

			size_t expected_size;
			size_t bytes_written;

			SHA256_CTX hash_ctx;

			bool active;
		};

		struct FileInfo {
			std::string name;
			uint64_t size_bytes;
			std::string sha256;
			uint64_t created_at;
		};

		explicit ClientStorageManager(const StorageConfig& config);

		DownloadHandle start_download(const std::string& name, size_t size);
		void write_chunk(DownloadHandle& handle, const uint8_t data, size_t len);
		void commit_download(DownloadHandle& handle);
		void abort_download(DownloadHandle& handle);
		
		FileInfo get_file_info(const std::string& path_str) const;
		void stream_file(std::string& path_str, StreamWriter& writer);

	private:
		StorageConfig config;

		std::string sanitize_filename(std::string name);
};
