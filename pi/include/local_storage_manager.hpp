#include <fcntl.h>
#include <filesystem>
#include <sodium.h>

#include "utils.hpp"
#include "file_stream_writer.hpp"
#include "crypto.hpp"

#pragma once

class LocalStorageManager
{
    public:
        struct StorageConfig {
        KeyManager key_manager;
        std::unique_ptr<SecureKey> MDK = std::make_unique<SecureKey>(KeyType::MASTER_DEVICE);

        std::string fek_context = "file_encryption_v1";
        uint64_t fek_subkey_id = 1;
        std::unique_ptr<SecureKey> FEK = std::make_unique<SecureKey>(KeyType::FILE_ENCRYPT, MDK->key_buf, fek_context, fek_subkey_id, false);

        enum Mode {
            ENCRYPT,
            DECRYPT
        };

        explicit LocalStorageManager(Mode local_mode, const std::string& source, const std::string& destination, bool create_metadata)
            : mode(local_mode), create_meta(create_metadata), src_path(source), dest_path(destination)
        {
            if (mode == ENCRYPT) {
                local_encrypt(src_path, dest_path);
            }
            else {
                local_decrypt(src_path, dest_path);
            }
        }
        
        void finalize(const std::string& tmp_path, const std::string& perm_path, bool create_meta);
        
        void local_encrypt(const std::string& src, const std::string& dest);
        void local_decrypt(const std::string& src, const std::string& dest);

    private:
        std::filesystem::path tmp_dir{PathMgr::strg_cfg_tmp};
        std::filesystem::path meta_dir{PathMgr::strg_cfg_meta}; // TODO - make creation of metadata optional for local uploads
        
        Mode mode;
        const std::string src_path;
        const std::string dest_path;
        bool create_meta = false;
        
        size_t file_size = 0;

        crypto_generichash_state hash_state;
        CryptoAtRest crypto_rest;
};
