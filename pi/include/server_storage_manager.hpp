#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <algorithm>
#include <sodium.h>

#include "utils.hpp"
#include "stream_writer.hpp"
#include "crypto.hpp"
#include "secure_mem.hpp"
#include "logger.hpp"

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
			UploadHandle() = default;

			int fd;
            
			std::filesystem::path tmp_path;
			std::filesystem::path final_path;
			std::filesystem::path meta_path;

			size_t expected_size;
			size_t bytes_written;
			
			crypto_generichash_state hash_state;
            std::unique_ptr<SecureSecretstreamState> encrypt_state;

			bool active;
			
			// non-moveable and non-copyable
			UploadHandle(const UploadHandle&) = delete;
    		UploadHandle& operator=(const UploadHandle&) = delete;
    		UploadHandle(UploadHandle&&) = delete;
    		UploadHandle& operator=(UploadHandle&&) = delete;
		};

		struct FileInfo {
			std::string name;
			uint64_t size_bytes;
			std::string sha256_str_hex;
			uint64_t created_at;
		};

        CryptoAtRest crypto_rest;
        CryptoInTransit crypto_transit;
        
		explicit ServerStorageManager(Logger& lgr, PathMgr& path_manager, SecureKey& fek)
			: logger(lgr), path_mgr(path_manager), FEK(fek), SESSION_KEY(nullptr) {}	
	
		void set_session_key(SecureKey& key)
		{
			SESSION_KEY = &key;
		}

		std::unique_ptr<UploadHandle> start_upload(const std::string& name, size_t size);
		void write_chunk(UploadHandle& handle, uint8_t* data, size_t len, bool final_chunk);
		void commit_upload(UploadHandle& handle);
		void abort_upload(UploadHandle& handle);

		FileInfo get_file_info(const std::string& name);
		std::vector<FileInfo> list_files();
		void delete_file(const std::string& name);
		
		void stream_file(std::string& name, StreamWriter& writer);

	private:
		Logger& logger;
        PathMgr& path_mgr;

        StorageConfig config {
			.root{path_mgr.strg_cfg_root}, 
			.files_dir{path_mgr.strg_cfg_files}, 
			.tmp_dir{path_mgr.strg_cfg_tmp}, 
			.meta_dir{path_mgr.strg_cfg_meta},
			.max_file_size = 1000000000, // 1GB
			.max_total_size = 10000000000, // 10GB
			.read_only = false
		};
				
        SecureKey& FEK;
        SecureKey* SESSION_KEY;
		
		std::string sanitize_filename(std::string name);

        void data_to_send(uint8_t* data, size_t len, StreamWriter& writer);
};
