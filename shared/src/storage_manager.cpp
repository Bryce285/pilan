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
	if (!handle.active) throw std::logic_error("Upload not active");

	write(handle.fd, data, len);
	SHA256_Update(&handle.hash_ctx, data, len);

	handle.bytes_written += len;
}

void StorageManager::commit_upload(UploadHandle& handle)
{
	if (handle.bytes_written != handle.expected_size) {
		throw std::runtime_error("File size mismatch");
	}

	fsync(handle.fd);
	close(handle.fd);

	rename(handle.tmp_path.c_str(), handle.final_path.c_str());
	
	// TODO - eventually use SQLite to store metadata
	// TODO - write metadata to json file

	handle.active = false;
}

void StorageManager::abort_upload(UploadHandle& handle)
{
	if (!handle.active) return;
	
	close(handle.fd);
	unlink(handle.tmp_path.c_str());

	handle.active = false;
}

FileInfo StorageManager::get_file_info(const std::string& name)
{
	// find and validate file

	// create a FileInfo object

	// fill out FileInfo object with file metadata
}

std::vector<FileInfo> StorageManager::list_files()
{
	// iterate through files directory

	// call get_file_info for each file and add to a vector

	// return vector
}

void StorageManager::delete_file(const std::string& name)
{
	// find and validate file

	// rename (name.deleting)

	// fsync

	// delete the file

	// delete metadata
}

void StorageManager::stream_file(std::string& name, StreamWriter& writer)
{
	// validate and open file
	// TODO - sanitize file name
	std::filesystem::path path = config.files_dir / name;	
	
	int fd = open(path.string().c_str(), O_RDONLY);
	if (fd < 0) {
		throw FileNotFound();
	}

	// read in chunks
	constexpr size_t CHUNK = 4 * 1024;
	uint8_t buffer[CHUNK];

	// streaming loop
	while (true) {
		ssize_t n = read(fd, buffer, CHUNK);
		if (n == 0) break;
		if (n < 0) throw IOError();
		
		writer.write(buffer, n);
	}

	// close file
	writer.flush();
	close(fd);
}
