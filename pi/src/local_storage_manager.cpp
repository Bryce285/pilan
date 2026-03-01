#include "local_storage_manager.hpp"

using json = nlohmann::json;

void LocalStorageManager::init(const PathMgr& path_mgr)
{
	tmp_dir = path_mgr.strg_cfg_tmp;
	meta_dir = path_mgr.strg_cfg_meta;	
}

void LocalStorageManager::finalize(std::string tmp_path, std::string perm_path)
{
    if (::rename(tmp_path.c_str(), perm_path.c_str()) != 0) {
        perror("Error finalizing upload");
    }
    
    if (create_meta && mode == Mode::ENCRYPT) {
		std::filesystem::path path = perm_path;
        std::filesystem::path perm_name = path.filename();
        std::filesystem::path meta_path = meta_dir / perm_name;

        uint8_t hash[crypto_generichash_BYTES];
        if (crypto_generichash_final(&hash_state, hash, crypto_generichash_BYTES) != 0) {
            throw std::runtime_error("Sodium error: could not finalize hash");
        }
        
        std::ofstream outFile(meta_path);
	    if (!outFile.is_open()) {
		    std::string error_msg = "Failed to open " + meta_path.string() + "\n";
		    throw std::runtime_error(error_msg);
	    }
	
	    constexpr size_t HASH_SIZE_HEX = (crypto_generichash_BYTES * 2) + 1;
        char hex[HASH_SIZE_HEX];
        
        json metadata;
	    metadata["name"] = perm_name;
	    metadata["size_bytes"] = file_size;
	    metadata["sha256_hex"] = sodium_bin2hex(hex, sizeof(hex), hash, crypto_generichash_BYTES);
	    metadata["created_at"] = std::to_string(Utils::unix_timestamp_ms());

	    outFile << metadata;
	    outFile.close();
    }
}

void LocalStorageManager::local_encrypt(std::string src, std::string dest)
{
    if (crypto_generichash_init(
			&hash_state, 
			nullptr, 
			0, 
			crypto_generichash_BYTES) != 0) {
    	throw std::runtime_error("Hash init failed");
    }

    std::filesystem::path dest_tmp = dest + ".tmp"; 
    std::filesystem::path tmp_path = tmp_dir / dest_tmp.filename();
    std::string tmp_path_str = tmp_path.string();

    int src_fd = open(src.c_str(), O_RDONLY);
    int dest_fd = open(tmp_path_str.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (src_fd < 0 || dest_fd < 0) {
		std::cerr << src << std::endl;
		std::cerr << tmp_path_str << std::endl;
        throw std::runtime_error("Failed to open file [local_storage_manager:65]");
    }

    file_size = std::filesystem::file_size(src);

    auto stream = crypto_rest.file_encrypt_init(dest_fd, FEK->key_buf);
    if (!stream) {
        throw std::runtime_error("init_push failed");
    }

    const size_t BUF_SIZE = 4096;
    std::vector<uint8_t> buffer(BUF_SIZE);

    while (true) {
        ssize_t n = read(src_fd, buffer.data(), BUF_SIZE);
        if (n < 0) {
            throw std::runtime_error("read failed");
        }

        
        if (n == 0) {
            crypto_rest.encrypt_chunk(
                dest_fd,
                stream,
                buffer.data(),
                0,
                true
            );
            break;
        }
        
        crypto_generichash_update(&hash_state, buffer.data(), n);

        bool is_last = (n < BUF_SIZE);
        
        crypto_rest.encrypt_chunk(
            dest_fd,
            stream,
            buffer.data(),
            n,
            is_last
        );
        
        if (is_last) break;
    }

    close(src_fd);
    close(dest_fd);

    finalize(tmp_path_str, dest);
}

void LocalStorageManager::local_decrypt(std::string src, std::string dest)
{
    std::filesystem::path dest_tmp = dest + ".tmp"; 
    std::filesystem::path tmp_path = tmp_dir / dest_tmp.filename();
    std::string tmp_path_str = tmp_path.string();

    int src_fd = open(src.c_str(), O_RDONLY);
    int dest_fd = open(tmp_path_str.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (src_fd < 0 || dest_fd < 0) {
        throw std::runtime_error("Failed to open file");
    }

    auto stream = crypto_rest.file_decrypt_init(src_fd, FEK->key_buf);
    if (!stream) {
        throw std::runtime_error("init pull failed");
    }

    FileStreamWriter writer(dest_fd);

    crypto_rest.decrypt_chunk(
        src_fd,
        stream,
        [](uint8_t* data, size_t len, StreamWriter& writer_l) {
            writer_l.write(data, len);
        },
        writer
    );

    close(src_fd);
    close(dest_fd);

    finalize(tmp_path_str, dest);
}
