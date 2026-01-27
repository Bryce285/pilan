#include "client_storage_manager.hpp"

ClientStorageManager::ClientStorageManager(const StorageConfig& config)
{
	this->config = config;
}

// TODO - this method is shared between the client and server storage managers
std::string ClientStorageManager::sanitize_filename(std::string name)
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

ClientStorageManager::DownloadHandle ClientStorageManager::start_download(const std::string& name, size_t size)
{
	std::string name_sanitized = sanitize_filename(name);
	DownloadHandle handle;

	handle.tmp_path = config.tmp_dir / (name_sanitized + ".tmp");
	handle.final_path = config.downloads_dir / name_sanitized;

	handle.fd = open(handle.tmp_path.c_str(),
						O_CREAT | O_EXCL | O_WRONLY,
						0600);

	handle.expected_size = size;
	handle.bytes_written = 0;
	handle.active = true;

	return handle;
}

void ClientStorageManager::write_chunk(DownloadHandle& handle, uint8_t* data, size_t len)
{
	if (!handle.active) throw std::logic_error("Download not active");

	write(handle.fd, data, len);
	handle.bytes_written += len;
}

void ClientStorageManager::commit_download(DownloadHandle& handle)
{
	if (handle.bytes_written != handle.expected_size) {
		throw std::runtime_error("File size mismatch");
	}

	rename(handle.tmp_path.c_str(), handle.final_path.c_str());

	fsync(handle.fd);
	close(handle.fd);

	handle.active = false;
}

void ClientStorageManager::abort_download(DownloadHandle& handle)
{
	if (!handle.active) return;

	close(handle.fd);
	unlink(handle.tmp_path.c_str());

	handle.active = false;
}

ClientStorageManager::FileInfo ClientStorageManager::get_file_info(const std::string& path_str)
{
	FileInfo file_info;
	std::filesystem::path path = path_str;
	
	file_info.name = path.filename();
	file_info.size_bytes = std::filesystem::file_size(path);

	return file_info;
}

void ClientStorageManager::stream_file(const std::string& path_str, StreamWriter& writer, const uint8_t* SESSION_KEY)
{
	std::filesystem::path path = path_str;
	std::string name = path.filename();
	std::string name_sanitized = sanitize_filename(name);

	FileInfo file_info = get_file_info(path_str);
	uint64_t size = file_info.size_bytes;

	//std::string header = "UPLOAD " + name_sanitized + " " + std::to_string(size) + "\n";

	//writer.write(header.c_str(), sizeof(header));

	int fd = open(path.string().c_str(), O_RDONLY);
	if (fd < 0) {
		throw std::runtime_error("File not found");
	}

	// read in chunks
	constexpr size_t CHUNK = 4 * 1024;
	uint8_t buffer[CHUNK];

	// streaming loop
	size_t total = 0;
	while (total < size) {
		ssize_t n = read(fd, buffer, CHUNK);
		if (n == 0) break;
		if (n < 0) throw std::runtime_error("IO error");

		crypto_transit.encrypt_message(buffer, writer.write, SESSION_KEY);
		total += n;
	}

	// close file
	writer.flush();
	close(fd);
}
