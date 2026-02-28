#include "local_storage_manager.hpp"

void LocalStorageManager::finalize(const std::string& tmp_path, const std::string& perm_path)
{
    if (::rename(tmp_path.c_str(), perm_path.c_str()) != 0) {
        perror("Error finalizing upload");
    }
}

void LocalStorageManager::local_encrypt(const std::string& src, const std::string& dest)
{
    std::string dest_tmp = dest + ".tmp";

    int src_fd = open(src.c_str(), O_RDONLY);
    int dest_fd = open(dest_tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (src_fd < 0 || dest_fd < 0) {
        throw std::runtime_error("Failed to open file");
    }

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

    finalize(dest_tmp, dest);
}

void LocalStorageManager::local_decrypt(const std::string& src, const std::string& dest)
{
    std::string dest_tmp = dest + ".tmp";

    int src_fd = open(src.c_str(), O_RDONLY);
    int dest_fd = open(dest_tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);

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

    finalize(dest_tmp, dest);
}
