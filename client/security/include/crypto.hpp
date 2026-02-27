#include <string>
#include <fstream>
#include <iostream>
#include <arpa/inet.h>
#include <filesystem>
#include <functional>
#include <sodium.h>

#include "paths.hpp"

#pragma once

class CryptoInTransit
{
    public:
		using DataSink = std::function<void(const uint8_t* data, size_t len)>;
       	
		static void write_tak(const std::string& tak); 
        static void load_tak(uint8_t key_buf[crypto_kdf_KEYBYTES]);
        void get_auth_tag(uint8_t* out_buf, uint8_t* server_nonce, uint8_t tak[crypto_kdf_KEYBYTES]);
		static void derive_session_key(uint8_t* key_buf, uint8_t tak[crypto_kdf_KEYBYTES]);
		
		void encrypt_message(uint8_t* plaintext, size_t plaintext_len, DataSink on_message_ready, uint8_t* session_key);
		void decrypt_message(uint8_t* ciphertext, size_t ciphertext_len, std::vector<uint8_t>& plaintext_out, uint8_t* session_key, uint8_t* nonce);
		
		void encrypted_string_send(std::string message, DataSink on_message_ready, uint8_t* session_key);

    private:
        inline static const std::filesystem::path TAK_PATH{PathMgr::tak_path}; 
		
		constexpr static size_t SALT_SIZE = 16;
		constexpr static size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
		constexpr static const char* HEADER = "TAK1";

		static void encrypt_tak(uint8_t key_buf[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]);
		static void decrypt_tak(uint8_t out_buf[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]);
};
