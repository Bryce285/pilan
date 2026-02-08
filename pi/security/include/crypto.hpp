#include <functional>
#include <vector>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <arpa/inet.h>

#include <sodium.h>

#include "key_manager.hpp"
#include "stream_writer.hpp"
#include "secure_mem.hpp"

#pragma once

class CryptoAtRest
{
    public:
        using PlaintextSink = std::function<void(uint8_t* data, size_t len, StreamWriter& writer)>;

        // TODO - use sodium_memzero and sodium_mlock to secure memory

        // TODO - make sure the recv buffers are the same size
        constexpr static size_t CHUNK_SIZE = 16348; // 16kB

        std::unique_ptr<SecureSecretstreamState> file_encrypt_init(int fd_out, const uint8_t* fek);
        void encrypt_chunk(int fd_out, std::unique_ptr<SecureSecretstreamState>& state, uint8_t* plaintext, size_t plaintext_len, const bool FINAL_CHUNK);

        std::unique_ptr<SecureSecretstreamState> file_decrypt_init(int fd_in, const uint8_t* fek);
        void decrypt_chunk(int fd_in, std::unique_ptr<SecureSecretstreamState>& state, PlaintextSink on_chunk_ready, StreamWriter& writer);
};

class CryptoInTransit
{
    public:
        using DataSink = std::function<void(const uint8_t* data, size_t len)>;

        // for client authentication
        void get_nonce(uint8_t out_buf[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]);
        bool verify_auth(uint8_t* auth_tag, const uint8_t* nonce, const uint8_t* tak);
        void derive_session_key(uint8_t* key_buf, const uint8_t* tak);

        void encrypt_message(uint8_t* plaintext, size_t plaintext_len, DataSink on_message_ready, uint8_t* session_key);
        void decrypt_message(uint8_t* ciphertext, size_t ciphertext_len, std::vector<uint8_t>& plaintext_out, const uint8_t* session_key, uint8_t* nonce);

        // this function is for ascii strings, not binary data
        void encrypted_string_send(std::string message, DataSink on_message_ready, uint8_t* session_key);
};
