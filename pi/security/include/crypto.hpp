#include <sodium.h>
#include "key_manager.hpp"

#pragma once

class Crypto
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
