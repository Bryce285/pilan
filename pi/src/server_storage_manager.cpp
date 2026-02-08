#include "server_storage_manager.hpp"

using json = nlohmann::json;

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

	handle.fd = ::open(handle.tmp_path.c_str(),
						O_CREAT | O_EXCL | O_WRONLY,
						0600);
	
	if (handle.fd == -1) {
		throw std::runtime_error("::open() failed");
	}

	handle.expected_size = size;
	handle.bytes_written = 0;
	handle.active = true;

    if (crypto_generichash_init(
			&handle.hash_state, 
			nullptr, 
			0, 
			crypto_generichash_BYTES) != 0) {
    	throw std::runtime_error("Hash init failed");
    }

    handle.encrypt_state = crypto_rest.file_encrypt_init(handle.fd, FEK.key_buf);

	return handle;	
}

void ServerStorageManager::write_chunk(UploadHandle& handle, uint8_t* data, size_t len, bool final_chunk)
{
	if (!handle.active) throw std::logic_error("Upload not active");

    if (crypto_generichash_update(&handle.hash_state, data, len) != 0) {
		throw std::runtime_error("Sodium error: hash update failed");
	}
    crypto_rest.encrypt_chunk(handle.fd, handle.encrypt_state, data, len, final_chunk);

	handle.bytes_written += len;
}

void ServerStorageManager::commit_upload(UploadHandle& handle)
{
	if (handle.bytes_written != handle.expected_size) {
		throw std::runtime_error("File size mismatch");
	}
	
	::rename(handle.tmp_path.c_str(), handle.final_path.c_str());

	::fsync(handle.fd);
	::close(handle.fd);
	
	uint8_t hash[crypto_generichash_BYTES];

    if (crypto_generichash_final(&handle.hash_state, hash, crypto_generichash_BYTES) != 0) {
        throw std::runtime_error("Sodium error: could not finalize hash");
    }

	std::ofstream outFile(handle.meta_path);
	if (!outFile.is_open()) {
		std::string error_msg = "Failed to open " + handle.meta_path.string() + "\n";
		throw std::runtime_error(error_msg);
	}
	
	constexpr size_t HASH_SIZE_HEX = (crypto_generichash_BYTES * 2) + 1;

    char hex[HASH_SIZE_HEX];

	// write name, size, hash, and creation timestamp to metadata file
	json metadata;
	metadata["name"] = handle.final_path.filename();
	metadata["size_bytes"] = handle.expected_size;
	metadata["sha256_hex"] = sodium_bin2hex(hex, sizeof(hex), hash, crypto_generichash_BYTES);
	metadata["created_at"] = std::to_string(unix_timestamp_ms());

	outFile << metadata;
	outFile.close();

	int dir_fd = ::open(config.meta_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (dir_fd >= 0) {
		::fsync(dir_fd);
		::close(dir_fd);
	}
	else if (dir_fd == -1) {
		std::cerr << "Failed to open file" << std::endl;
	}

	handle.active = false;
}

// TODO - figure out where to use this method
void ServerStorageManager::abort_upload(UploadHandle& handle)
{
	if (!handle.active) return;
	
	::close(handle.fd);
	::unlink(handle.tmp_path.c_str());

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

// TODO - when opening files should we throw an error or just print one?
void ServerStorageManager::delete_file(const std::string& name)
{
	// find and validate file
	std::filesystem::path path = config.files_dir / sanitize_filename(name);	
	std::filesystem::path path_deleting = path.parent_path() / (path.filename().string() + ".deleting");

	// rename (name.deleting)
	std::filesystem::rename(path, path_deleting);

	int dir_fd = open(config.files_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (dir_fd >= 0) {
		::fsync(dir_fd);
		::close(dir_fd);
	}
	else if (dir_fd == -1) {
		std::cerr << "Failed to open file" << std::endl;
	}
	
	// delete the file
	std::filesystem::remove(path_deleting);

	dir_fd = open(config.files_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (dir_fd >= 0) {
		::fsync(dir_fd);
		::close(dir_fd);
	}
	else if (dir_fd == -1) {
		std::cerr << "Failed to open file" << std::endl;
	}

	// delete metadata
	std::filesystem::path meta_path = config.meta_dir / (name + ".json");
	std::filesystem::path meta_path_deleting = meta_path.parent_path() / (meta_path.filename().string() + ".deleting");

	std::filesystem::rename(meta_path, meta_path_deleting);

	int meta_dir_fd = open(config.meta_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (meta_dir_fd >= 0) {
		::fsync(meta_dir_fd);
		::close(meta_dir_fd);
	}

	std::filesystem::remove(meta_path_deleting);

	meta_dir_fd = open(config.meta_dir.c_str(), O_DIRECTORY | O_RDONLY);
	if (meta_dir_fd >= 0) {
		::fsync(meta_dir_fd);
		::close(meta_dir_fd);
	}
}

void ServerStorageManager::data_to_send(uint8_t* data, size_t len, StreamWriter& writer)
{
	if (!SESSION_KEY) {
		throw std::logic_error("Session key not initialized");
	}

    crypto_transit.encrypt_message(
		data,
		len, 
		[&](const uint8_t* data_l, size_t len_l) {
			writer.write(data_l, len_l); 
		}, 
		SESSION_KEY->key_buf
	);
}

void ServerStorageManager::stream_file(std::string& name, StreamWriter& writer)
{
	// validate and open file
	std::filesystem::path path = config.files_dir / sanitize_filename(name);	
	
	/*
	FileInfo file_info = get_file_info(name);
	uint64_t size = file_info.size_bytes;
	*/

	int fd = ::open(path.string().c_str(), O_RDONLY);
	if (fd < 0) {
		throw std::runtime_error("Failed to open file");
	}
    
    std::unique_ptr<SecureSecretstreamState> decrypt_state = crypto_rest.file_decrypt_init(fd, FEK.key_buf);

    crypto_rest.decrypt_chunk(
		fd, 
		decrypt_state, 
		[&](uint8_t* data, size_t len, StreamWriter& writer_l) {
			data_to_send(data, len, writer_l); 
		}, 
		writer
	);

	// close file
	writer.flush();
	::close(fd);
}
