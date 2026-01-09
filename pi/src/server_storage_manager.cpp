#include "server_storage_manager.hpp"

using json = nlohmann::json;

ServerStorageManager::StorageManager(const StorageConfig& config) 
{
	this->config = config;
}

uint64_t ServerStorageManager::unix_timestamp_ms()
{
	using namespace std::chrono;
    return duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()
    ).count();
}

std::string ServerStorageManager::sanitize_filename(std::string name)
{
	const std::string invalid_chars = R"literal(<>:\"/\\|?*)literal";
	for (char c : invalid_chars) {
		std::replace(name.begin(), name.end(), c, '_');
	}
	
	filename.erase(std::remove_if(filename.begin(), filename.end(), [](unsigned char x) {
        return std::iscntrl(x);
    }), filename.end());

	while (name.find("..") != std::string::npos) {
        size_t pos = name.find("..");
        name.replace(pos, 2, "");
    }

	return name;
}

UploadHandle ServerStorageManager::start_upload(const std::string& name, size_t size)
{
	std::string name_sanitized = sanitize_filename(name);
	UploadHandle handle;

	handle.tmp_path = config.tmp_dir / (name_sanitized + ".tmp");
	handle.final_path = config.files_dir / name_sanitized;
	handle.meta_path = config.meta_dir / (name_sanitized + ".json");

	handle.fd = open(handle.tmp_path.c_str(),
						O_CREAT | O_EXCL | O_WRONLY,
						0600);

	handle.expected_size = size;
	handle.bytes_written = 0;
	handle.active = true;

	SHA256_Init(&handle.hash_ctx);	

	return handle;	
}

void ServerStorageManager::write_chunk(UploadHandle& handle, const uint8_t data, size_t len)
{
	if (!handle.active) throw std::logic_error("Upload not active");

	write(handle.fd, data, len);
	SHA256_Update(&handle.hash_ctx, data, len);

	handle.bytes_written += len;
}

void ServerStorageManager::commit_upload(UploadHandle& handle)
{
	if (handle.bytes_written != handle.expected_size) {
		throw std::runtime_error("File size mismatch");
	}
	
	rename(handle.tmp_path.c_str(), handle.final_path.c_str());

	fsync(handle.fd);
	close(handle.fd);
	
	// TODO - eventually use SQLite to store metadata
	
	std::ofstream outFile(handle.meta_path);
	if (!outFile.is_open()) {
		std::cerr << "Failed to open " << handle.meta_path.string() << std::endl;
	}
	
	// write name, size, hash, and creation timestamp to metadata file
	json metadata;
	metadata["name"] = handle.final_path.filename();
	metadata["size_bytes"] = handle.expected_size;
	metadata["sha256"] = handle.hash_ctx;
	metadata["created_at"] = std::to_string(unix_timestamp_ms());

	outFile << metadata;
	outFile.close();

	int dir_fd = open(config.meta_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (dir_fd >= 0) {
		fsync(dir_fd);
		close(dir_fd);
	}

	handle.active = false;
}

// TODO - figure out where to use this method
void ServerStorageManager::abort_upload(UploadHandle& handle)
{
	if (!handle.active) return;
	
	close(handle.fd);
	unlink(handle.tmp_path.c_str());

	handle.active = false;
}

FileInfo ServerStorageManager::get_file_info(const std::string& name)
{
	// find and validate file
	std::filesystem::path path = config.files_dir / sanitize_filename(name) + ".json";	

	// create a FileInfo object
	FileInfo file_info;

	// fill out FileInfo object with file metadata
	std::ifstream inFile(path);
	json metadata{json::parse(inFile)};
	
	file_info.name = metadata["name"];
	file_info.size_bytes = static_cast<uint64_t>(metadata["size_bytes"]);
	file_info.sha256 = metadata["sha256"];
	file_info.created_at = static_cast<uint64_t>(metadata["created_at"]);

	inFile.close();
	return file_info;
}

std::vector<FileInfo> ServerStorageManager::list_files()
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

	return files;
}

void ServerStorageManager::delete_file(const std::string& name)
{
	// find and validate file
	std::filesystem::path path = config.files_dir / sanitize_filename(name);	
	std::filesystem::path path_deleting = path + ".deleting";

	// rename (name.deleting)
	std::filesystem::rename(path, path_deleting);

	int dir_fd = open(config.files_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (dir_fd >= 0) {
		fsync(dir_fd);
		close(dir_fd);
	}
	
	// TODO - add some error handling
	// delete the file
	std::filesystem::remove(path_deleting);

	int dir_fd = open(config.files_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (dir_fd >= 0) {
		fsync(dir_fd);
		close(dir_fd);
	}

	// delete metadata
	std::filesystem::path meta_path = config.meta_dir / name + ".json";
	std::filesystem::path meta_path_deleting = meta_path + ".deleting";

	std::filesystem::rename(meta_path, meta_path_deleting);

	int meta_dir_fd = open(config.meta_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (meta_dir_fd >= 0) {
		fsync(meta_dir_fd);
		close(meta_dir_fd);
	}

	std::filesystem::remove(meta_path_deleting);

	int meta_dir_fd = open(config.meta_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (meta_dir_fd >= 0) {
		fsync(meta_dir_fd);
		close(meta_dir_fd);
	}
}

void ServerStorageManager::stream_file(std::string& name, StreamWriter& writer)
{
	// validate and open file
	std::filesystem::path path = config.files_dir / sanitize_filename(name);	
	FileInfo file_info = get_file_info(name);
	uint64_t size = file_info.size_bytes;

	std::string header = "DOWNLOAD " + name + " " + std::to_string(size) + "\n";
	
	writer.write(header.c_str(), sizeof(header));

	int fd = open(path.string().c_str(), O_RDONLY);
	if (fd < 0) {
		throw FileNotFound();
	}

	// read in chunks
	constexpr size_t CHUNK = 4 * 1024;
	uint8_t buffer[CHUNK];

	// streaming loop
	size_t total = 0;
	while (total < size) {
		ssize_t n = read(fd, buffer, CHUNK);
		if (n == 0) break;
		if (n < 0) throw IOError();
		
		writer.write(buffer, n);
		total += n;
	}

	// close file
	writer.flush();
	close(fd);
}
