#include <fcntl.h>
#include <filesystem>
#include <sodium.h>

#include "file_stream_writer.hpp"
#include "crypto.hpp"

#pragma once

class LocalStorageManager
{
    public:
        /*
        struct StorageConfig {
            std::filesystem::path files_dir;
            std::filesystem::path tmp_dir;
            std::filesystem::path meta_dir; // create a metadata file for compatibility with server mode. TODO - make generation of this file optional

            bool read_only;
        };
        */
        
        /*
        explicit LocalStorageManager(const StorageConfig& cfg, SecureKey& fek)
            : config(cfg) {}
        */

        KeyManager key_manager;
        std::unique_ptr<SecureKey> MDK = std::make_unique<SecureKey>(KeyType::MASTER_DEVICE);

        std::string fek_context = "file_encryption_v1";
        uint64_t fek_subkey_id = 1;
        std::unique_ptr<SecureKey> FEK = std::make_unique<SecureKey>(KeyType::FILE_ENCRYPT, MDK->key_buf, fek_context, fek_subkey_id, false);

        enum Mode {
            ENCRYPT,
            DECRYPT
        };

        explicit LocalStorageManager(Mode local_mode, const std::string& source, const std::string& destination)
            : mode(local_mode), src_path(source), dest_path(destination)
        {
            if (mode == ENCRYPT) {
                local_encrypt(src_path, dest_path);
            }
            else {
                local_decrypt(src_path, dest_path);
            }
        }

        void finalize(const std::string& tmp_path, const std::string& perm_path);
        
        void local_encrypt(const std::string& src, const std::string& dest);
        void local_decrypt(const std::string& src, const std::string& dest);

    private:
        Mode mode;
        const std::string src_path;
        const std::string dest_path;

        //StorageConfig config;
        CryptoAtRest crypto_rest;
};
