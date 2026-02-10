#include <string>
#include <fstream>
#include <iostream>
#include <arpa/inet.h>
#include <filesystem>
#include <functional>
#include <sodium.h>

#pragma once

class CryptoInTransit
{
    public:
		using DataSink = std::function<void(const uint8_t* data, size_t len)>;
        
        static void load_tak(uint8_t key_buf[crypto_kdf_KEYBYTES]);
        void get_auth_tag(uint8_t* out_buf, uint8_t* server_nonce);
		static void derive_session_key(uint8_t* key_buf);
		
		void encrypt_message(uint8_t* plaintext, size_t plaintext_len, DataSink on_message_ready, uint8_t* session_key);
		void decrypt_message(uint8_t* ciphertext, size_t ciphertext_len, std::vector<uint8_t>& plaintext_out, uint8_t* session_key, uint8_t* nonce);
		
		void encrypted_string_send(std::string message, DataSink on_message_ready, uint8_t* session_key);

    private:

        // TODO - TAK storage as plaintext is for testing only, should be replaced by some kind of config file
        inline static const std::filesystem::path TAK_PATH = "/home/bryce/projects/offlinePiFS/client/tak_tmp_path/tak.txt";
};
