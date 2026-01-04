#include "storage_manager.hpp"

StorageManager::StorageManager(const StorageConfig& config) 
{
	this->config = config;
}

UploadHandle StorageManager::start_upload(const std::string& name, size_t size)
{
	UploadHandle handle;

	handle.tmp_path = config.tmp_dir / (name + ".tmp");
	handle.final_path = config.files_dir / name;
	handle.meta_path = config.meta_dir / (name + ".json");

	handle.fd = open(handle.tmp_path.c_str(),
						O_CREAT | O_EXCL | O_WRONLY,
						0600);

	handle.expected_size = size;
	handle.bytes_written = 0;
	handle.active = true;

	SHA256_Init(&handle.hash_ctx);	

	return handle;	
}

void StorageManager::write_chunk(UploadHandle& handle, const uint8_t data, size_t len)
{

}

void StorageManager::commit_upload(UploadHandle& handle)
{

}

void StorageManager::abort_upload(UploadHandle& handle)
{

}

FileInfo StorageManager::get_file_info(const std::string& name)
{

}

std::vector<FileInfo> StorageManager::list_files()
{

}

void StorageManager::delete_file(const std::string& name)
{

}
