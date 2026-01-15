#include "crypto.hpp"

crypto_secretstream_xchacha20poly1305_state Crypto::file_encrypt_init(int fd_out)
{
    crypto_secretstream_xchacha20poly1305_state state;
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    // TODO - is it safe to store the key as a string here?
    std::string fek; // TODO - get this from derive_key method in KeyManager

    crypto_secretstream_xchacha20poly1305_init_push(&state, header, fek);

    write(fd_out, header, sizeof(header));
    return state;
}

void Crypto::encrypt_chunk(int fd_out, crypto_secretstream_xchacha20poly1305_state& state, uint8_t* plaintext, const bool FINAL_CHUNK)
{
    const size_t PLAINTEXT_LEN = std::size(plaintext);
    const size_t CIPHERTEXT_LEN = PLAINTEXT_LEN + crypto_secret_stream_xchacha20poly1305_ABYTES;
    uint8_t ciphertext[CIPHERTEXT_LEN];
    
    if (!FINAL_CHUNK) {
        crypto_secretstream_xchacha20poly1305_push (
                &state,
                ciphertext,
                &CIPHERTEXT_LEN,
                plaintext,
                PLAINTEXT_LEN,
                nullptr,
                0,
                0
            );
    }
    else {
        crypto_secretstream_xchacha20poly1305_push (
                &state,
                ciphertext,
                &CIPHERTEXT_LEN,
                plaintext,
                PLAINTEXT_LEN,
                nullptr,
                0,
                crypto_secretstream_xchacha20poly1305_TAG_FINAL
            );
    }

    write(fd_out, ciphertext, CIPHERTEXT_LEN);
}

crypto_secretstream_xchacha20poly1305_state Crypto::file_decrypt_init(int fd_in)
{
    crypto_secretstream_xchacha20poly1305_state state;
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    std::string fek; // TODO - get this from derive key method in key manager

    read(fd_in, header, sizeof(header));

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, fek) != 0) {
        std::cerr << "Failed to initialize secretstream pull" << std::endl; 
    }
    
    return state;
}

void Crypto::decrypt_chunk(int fd_in, crypto_secretstream_xchacha20poly1305_state& statePlaintextSink on_chunk_ready)
{
    uint8_t plaintext[CHUNK_SIZE];

    const size_t PLAINTEXT_LEN = CHUNK_SIZE;
    const size_t CIPHERTEXT_LEN = CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
    uint8_t ciphertext[CIPHERTEXT_LEN];
    uint8_t tag;

    while ((n = read(fd_in, ciphertext, CIPHERTEXT_LEN)) > 0) {
        if (crypto_secretstream_xchacha20poly1305_pull(
                    &state,
                    plaintext,
                    &PLAINTEXT_LEN,
                    &tag,
                    ciphertext,
                    CIPHERTEXT_LEN,
                    nullptr,
                    0
                ) != 0) {
            std::cerr << "Failed to pull ciphertext" std::endl;
            return;
        }

        on_chunk_ready(plaintext, PLAINTEXT_LEN);

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            break;
        }
    }
}
