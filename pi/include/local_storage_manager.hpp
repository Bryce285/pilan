#include <fcntl.h>
#include <filesystem>
#include <sodium.h>
#include <nlohmann/json.hpp>

#include "utils.hpp"
#include "file_stream_writer.hpp"
#include "crypto.hpp"
#include "paths.hpp"

#pragma once

class LocalStorageManager
{
    public:
        KeyManager key_manager;
        std::unique_ptr<SecureKey> MDK = std::make_unique<SecureKey>(KeyType::MASTER_DEVICE);

        std::string fek_context = "file_encryption_v1";
        uint64_t fek_subkey_id = 1;
        std::unique_ptr<SecureKey> FEK = std::make_unique<SecureKey>(KeyType::FILE_ENCRYPT, MDK->key_buf, fek_context, fek_subkey_id, false);

        enum class Mode {
            ENCRYPT,
            DECRYPT
        };

        explicit LocalStorageManager(LocalStorageManager::Mode local_mode, std::string source, std::string destination, bool create_metadata)
            : mode(local_mode), src_path(source), dest_path(destination), create_meta(create_metadata)
        {
            if (mode == Mode::ENCRYPT) {
                local_encrypt(src_path, dest_path);
            }
            else {
                local_decrypt(src_path, dest_path);
            }
        }
       	
		static void init(const PathMgr& path_mgr); 
        void finalize(std::string tmp_path, std::string perm_path);
        
        void local_encrypt(std::string src, std::string dest);
        void local_decrypt(std::string src, std::string dest);

    private: 
        inline static std::filesystem::path tmp_dir;
        inline static std::filesystem::path meta_dir; 
        
        Mode mode;
        std::string src_path;
        std::string dest_path;
        bool create_meta = false;
        
        size_t file_size = 0;

        crypto_generichash_state hash_state;
        CryptoAtRest crypto_rest;
};
