#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "stream_writer.hpp"
#include "crypto.hpp"

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

			bool active;
		};

		struct FileInfo {
			std::string name;
			uint64_t size_bytes;
		};

		explicit ClientStorageManager(const StorageConfig& config);
		
		CryptoInTransit crypto_transit;

		DownloadHandle start_download(const std::string& name, size_t size);
		void write_chunk(DownloadHandle& handle, uint8_t* data, size_t len);
		void commit_download(DownloadHandle& handle);
		void abort_download(DownloadHandle& handle);
		
		FileInfo get_file_info(const std::string& path_str);
		void stream_file(const std::string& path_str, StreamWriter& writer, uint8_t* session_key);

	private:
		StorageConfig config;

		std::string sanitize_filename(std::string name);
};
