#include "crypto.hpp"

// TODO - make sure that full error handling and secure failure are implemented

crypto_secretstream_xchacha20poly1305_state CryptoAtRest::file_encrypt_init(int fd_out, const uint8_t* fek)
{
    crypto_secretstream_xchacha20poly1305_state state;
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_init_push(&state, header, fek);

    write(fd_out, header, sizeof(header));
    return state;
}

void CryptoAtRest::encrypt_chunk(int fd_out, crypto_secretstream_xchacha20poly1305_state& state, uint8_t* plaintext, const bool FINAL_CHUNK)
{
    const size_t PLAINTEXT_LEN = std::size(plaintext);

    // TODO - I don't think ciphertext length should be set here as it is set by the push function
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

crypto_secretstream_xchacha20poly1305_state CryptoAtRest::file_decrypt_init(int fd_in, const uint8_t* fek)
{
    crypto_secretstream_xchacha20poly1305_state state;
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    read(fd_in, header, sizeof(header));

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, fek) != 0) {
        std::cerr << "Failed to initialize secretstream pull" << std::endl; 
    }
    
    return state;
}

void CryptoAtRest::decrypt_chunk(int fd_in, crypto_secretstream_xchacha20poly1305_state& state, PlaintextSink on_chunk_ready)
{
    // TODO - should we just set the plaintext buffer to CHUNK_SIZE or should we use the same strategy that we use in the decrypt_message function?
    uint8_t plaintext[CHUNK_SIZE];
    
    // TODO - i don't think plaintext length should be set as it is returned by the pull function
    const size_t PLAINTEXT_LEN = CHUNK_SIZE;
    const size_t CIPHERTEXT_LEN = CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
    uint8_t ciphertext[CIPHERTEXT_LEN];
    uint8_t tag;
    
    ssize_t n;
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

uint8_t* CryptoInTransit::get_nonce()
{
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    return nonce;
}

bool CryptoInTransit::verify_auth(uint8_t* auth_tag, const uint8_t* nonce, const uint8_t* tak)
{
    if (crypto_auth_hmacsha256_verify(
            auth_tag,
            nonce,
            sizeof(nonce),
            tak
        ) != 0) {
        std::cerr << "Failed to verify auth" << std::endl;
        return false;
    }
    else return true;
}

void CryptoInTransit::derive_session_key(uint8_t* key_buf, const uint8_t* tak)
{
    crypto_kdf_derive_from_key(
            key_buf,
            sizeof(key_buf),
            1,
            "FILEXFER",
            tak
        );
}

// we recieve decrypted file data in chunks from the decrypt_chunk function, we then call this function on each decrypted chunk, and send the output to the client 
void CryptoInTransit::encrypt_message(uint8_t* plaintext, DataSink on_message_ready, uint8_t* session_key)
{
    const size_t PLAINTEXT_LEN = std::size(plaintext);

    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    uint32_t ciphertext_len;
    uint8_t ciphertext[PLAINTEXT_LEN + crypto_aead_xchacha20poly1305_ietf_ABYTES];

    crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext,
            &ciphertext_len,
            plaintext,
            PLAINTEXT_LEN,
            nullptr, 0,
            nullptr,
            nonce,
            session_key
        );
    
    /*
     *  CHUNK MESSAGE PROTOCOL:
     *  [ciphertext length (network byte order]
     *  [nonce (24 bytes)]
     *  [ciphertext + auth tag]
     */
    on_message_ready(htonl(ciphertext_len), sizeof(uint32_t));
    on_message_ready(nonce, sizeof(nonce));
    on_message_ready(ciphertext, CIPHERTEXT_LEN);
}

void CryptoInTransit::decrypt_message(uint8_t* ciphertext, std::vector<uint8_t>& plaintext_out, uint8_t* session_key, uint8_t* nonce)
{
    const size_t CIPHERTEXT_LEN = std::size(ciphertext);
    if (CIPHERTEXT_LEN < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        std::cerr << "Ciphertext length is less than authentication tag size" << std::endl;
        return;
    }
    
    // TODO - can just edit the caller provided plaintext buffer in-place
    std::vector<uint8_t> plaintext(CIPHERTEXT_LEN);
    size_t plaintext_len;

    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(),
            &plaintext_len,
            nullptr,
            ciphertext,
            CIPHERTEXT_LEN,
            nullptr, 0,
            nonce,
            session_key
        );

    if (rc != 0) {
        // TODO - drop packet and disconnect client
        sodium_memzero(plaintext.data(), plaintext.size());
        std::cerr << "auth failed" << std::endl;
    }

    plaintext.resize(plaintext_len);
    plaintext_out = plaintext;
}

bool CryptoInTransit::encrypted_string_send(std::string message, DataSink on_message_ready uint8_t* session_key)
{
    const uint8_t* data = reinterpret_cast<const uint8_t*>(message.data());
    encrypt_message(data, on_message_ready, session_key);
}
