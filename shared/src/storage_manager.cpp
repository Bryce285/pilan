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
	// TODO - write metadata to json file (remember to fsync)

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
	std::filesystem::path path = config.files_dir / name;	

	// create a FileInfo object
	FileInfo file_info;

	// fill out FileInfo object with file metadata
	// TODO - open and parse json metadata file

	return file_info;
}

std::vector<FileInfo> StorageManager::list_files()
{
	std::vector<FileInfo> files;

	// iterate through files directory
	try {
		for (const auto& file : std::filesystem::directory_iterator(config.files_dir)) {
			if (std::filesystem::is_regular_file(file.status())) {
				files.push_back(get_file_info(file.string()));
			}
		}
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
	}

	// return vector
	return files;
}

void StorageManager::delete_file(const std::string& name)
{
	// find and validate file
	std::filesystem::path path = config.files_dir / name;	

	// rename (name.deleting)
	std::filesystem::rename(path, path + ".deleting");

	int dir_fd = open(parent_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (dir_fd >= 0) {
		fsync(dir_fd);
		close(dir_fd);
	}

	// delete the file
	// TODO - check that this deletes the renamed path
	std::filsystem::remove(path);

	int dir_fd = open(parent_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (dir_fd >= 0) {
		fsync(dir_fd);
		close(dir_fd);
	}

	// delete metadata
	// TODO - delete json metadata file (remember to fsync)
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
