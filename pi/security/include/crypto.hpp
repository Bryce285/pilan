#include <sodium.h>
#include "key_manager.hpp"

#pragma once

class CryptoAtRest
{
    public:
        using PlaintextSink = std::function<void(const uint8_t* data, size_t len)>;

        // TODO - use sodium_memzero and sodium_mlock to secure memory

        // TODO - make sure the recv buffers is the same size
        const size_t CHUNK_SIZE = 16348; // 16kB

        crypto_secretstream_xchacha20poly1305_state file_encrypt_init(int fd_out);
        void encrypt_chunk(int fd_out, crypto_secretstream_xchacha20poly1305_state& state, uint8_t* plaintext, const bool FINAL_CHUNK);

        crypto_secretstream_xchacha20poly1305_state file_decrypt_init(int fd_in);
        void decrypt_chunk(int fd_in, crypto_secretstream_xchacha20poly1305_state& state, PlaintextSink on_chunk_ready);
};

class CryptoInTransit
{
    public:
        using DataSink = std::function<void(const uint8_t* data, size_t len)>;
        
        // for client authentication
        uint8_t* get_nonce();
        bool verify_auth(uint8_t* auth_tag);
        void derive_session_key(uint8_t* key_buf, const uint8_t* tak);

        void encrypt_message(uint8_t* plaintext, DataSink on_message_ready, uint8_t* session_key);
        void decrypt_message(uint8_t* ciphertext, DataSink on_message_ready, uint8_t* session_key, uint8_t* nonce);

    private:
        const size_t AUTH_NONCE_LEN = 32;
};
