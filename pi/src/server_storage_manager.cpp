#include "server_storage_manager.hpp"

using json = nlohmann::json;

ServerStorageManager::ServerStorageManager(const ServerStorageManager::StorageConfig& config) 
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
	
	name.erase(std::remove_if(name.begin(), name.end(), [](unsigned char x) {
        return std::iscntrl(x);
    }), name.end());

	while (name.find("..") != std::string::npos) {
        size_t pos = name.find("..");
        name.replace(pos, 2, "");
    }

	return name;
}

ServerStorageManager::UploadHandle ServerStorageManager::start_upload(const std::string& name, size_t size)
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

    if (crypto_generichash_init(&handle.hash_state, nullptr, 0, HASH_SIZE) != 0) {
        std::cerr << "hash init failed" << std::endl;
    }

    // TODO - need a CryptoAtRest object here
    handle.encrypt_state = file_encrypt_init(handle.fd, FEK);

	return handle;	
}

void ServerStorageManager::write_chunk(UploadHandle& handle, const uint8_t* data, size_t len, bool final_chunk)
{
	if (!handle.active) throw std::logic_error("Upload not active");

    crypto_generichash_update(&handle.hash_state, data, len);

    // TODO - we need to somehow get access to crypto.hpp here to use this function
    encrypt_chunk(handle.fd, handle.encrypt_state, data, final_chunk);

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
	
	uint8_t hash[HASH_SIZE];

    if (crypto_generichash_final(&handle.hash_state, hash, HASH_SIZE) != 0) {
        std::cerr << "Could not finalize hash" << std::endl;
    }

	// TODO - eventually use SQLite to store metadata
	
	std::ofstream outFile(handle.meta_path);
	if (!outFile.is_open()) {
		std::cerr << "Failed to open " << handle.meta_path.string() << std::endl;
	}
	
    char hex[(HASH_SIZE * 2) + 1];

	// write name, size, hash, and creation timestamp to metadata file
	json metadata;
	metadata["name"] = handle.final_path.filename();
	metadata["size_bytes"] = handle.expected_size;
	metadata["sha256_hex"] = sodium_bin2hex(hex, sizeof(hex), hash, HASH_SIZE);
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

ServerStorageManager::FileInfo ServerStorageManager::get_file_info(const std::string& name)
{
	// find and validate file
	std::filesystem::path path = config.meta_dir / (sanitize_filename(name) + ".json");	

	// create a FileInfo object
	FileInfo file_info;

	// fill out FileInfo object with file metadata
	std::ifstream inFile(path);
	json metadata{json::parse(inFile)};

	const auto& meta = metadata.at(0);

	file_info.name = meta.at("name").get<std::string>();
	file_info.size_bytes = meta.at("size_bytes").get<uint64_t>();
	file_info.sha256_str_hex = meta.at("sha256_hex").get<std::string>();
	file_info.created_at = std::stoull(meta.at("created_at").get<std::string>());

	inFile.close();
	return file_info;
}

std::vector<ServerStorageManager::FileInfo> ServerStorageManager::list_files()
{
	std::vector<FileInfo> files;

	// iterate through files directory
	try {
		for (const auto& file : std::filesystem::directory_iterator(config.files_dir)) {
			if (std::filesystem::is_regular_file(file.status())) {
				files.push_back(get_file_info(file.path().filename().string()));
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
	std::filesystem::path path_deleting = path.parent_path() / (path.filename().string() + ".deleting");

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

	dir_fd = open(config.files_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (dir_fd >= 0) {
		fsync(dir_fd);
		close(dir_fd);
	}

	// delete metadata
	std::filesystem::path meta_path = config.meta_dir / (name + ".json");
	std::filesystem::path meta_path_deleting = meta_path.parent_path() / (meta_path.filename().string() + ".deleting");

	std::filesystem::rename(meta_path, meta_path_deleting);

	int meta_dir_fd = open(config.meta_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (meta_dir_fd >= 0) {
		fsync(meta_dir_fd);
		close(meta_dir_fd);
	}

	std::filesystem::remove(meta_path_deleting);

	meta_dir_fd = open(config.meta_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (meta_dir_fd >= 0) {
		fsync(meta_dir_fd);
		close(meta_dir_fd);
	}
}

void ServerStorageManager::data_to_send(const uint8_t* data, size_t len)
{
    // TODO - need a CryptoInTransit object to call this
    encrypt_message(data, writer.write, SESSION_KEY);
}

void ServerStorageManager::stream_file(std::string& name, StreamWriter& writer)
{
	// validate and open file
	std::filesystem::path path = config.files_dir / sanitize_filename(name);	
	FileInfo file_info = get_file_info(name);
	uint64_t size = file_info.size_bytes;
	
	// TODO - add to stream writer a function to send ascii data so that headers can be sent from here
	//std::string header = "DOWNLOAD " + name + " " + std::to_string(size) + "\n";
	
	//writer.write(header.c_str(), sizeof(header));
    
	int fd = open(path.string().c_str(), O_RDONLY);
	if (fd < 0) {
		throw std::runtime_error("File not found");
	}
    
    crypto_secretstream_xchacha20poly1305_state decrypt_state = file_decrypt_init(fd, FEK);

    // TODO - need a CryptoAtRest object to call this function
    decrypt_chunk(fd, decrypt_state, data_to_send);

	// close file
	writer.flush();
	close(fd);
}
