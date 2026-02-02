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

void CryptoAtRest::encrypt_chunk(int fd_out, crypto_secretstream_xchacha20poly1305_state& state, uint8_t* plaintext, size_t plaintext_len, const bool FINAL_CHUNK)
{
    unsigned long long ciphertext_len = 0;

    std::vector<uint8_t> ciphertext(plaintext_len + crypto_secretstream_xchacha20poly1305_ABYTES);

    const uint8_t tag = FINAL_CHUNK
        ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : 0;

    crypto_secretstream_xchacha20poly1305_push(
        &state,
        ciphertext.data(),
        &ciphertext_len,
        plaintext,
        plaintext_len,
        nullptr,
        0,
        tag
    );

    write(fd_out, ciphertext.data(), ciphertext_len);
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

void CryptoAtRest::decrypt_chunk(int fd_in, crypto_secretstream_xchacha20poly1305_state& state, PlaintextSink on_chunk_ready, StreamWriter& writer)
{
    // TODO - should we just set the plaintext buffer to CHUNK_SIZE or should we use the same strategy that we use in the decrypt_message function?
    uint8_t plaintext[CHUNK_SIZE];
    
    unsigned long long plaintext_len;
    constexpr size_t CIPHERTEXT_LEN = CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
    uint8_t ciphertext[CIPHERTEXT_LEN];
    uint8_t tag;
    
    ssize_t n;
    while ((n = read(fd_in, ciphertext, CIPHERTEXT_LEN)) > 0) {
        if (crypto_secretstream_xchacha20poly1305_pull(
                    &state,
                    plaintext,
                    &plaintext_len,
                    &tag,
                    ciphertext,
                    n,
                    nullptr,
                    0
                ) != 0) {
            std::cerr << "Failed to pull ciphertext" << std::endl;
            return;
        }

        on_chunk_ready(plaintext, plaintext_len, writer);

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            break;
        }
    }
}

void CryptoInTransit::get_nonce(uint8_t out_buf[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
{
    randombytes_buf(out_buf, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
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
            crypto_kdf_KEYBYTES,
            1,
            "FILEXFER",
            tak
        );
}

// we recieve decrypted file data in chunks from the decrypt_chunk function, we then call this function on each decrypted chunk, and send the output to the client 
void CryptoInTransit::encrypt_message(const uint8_t* plaintext, size_t plaintext_len, DataSink on_message_ready, uint8_t* session_key)
{
	uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    unsigned long long ciphertext_len;
    std::vector<uint8_t> ciphertext(plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES);

	crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(),
            &ciphertext_len,
            plaintext,
            plaintext_len,
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

	uint32_t net_len = htonl(ciphertext_len);
	
	std::vector<uint8_t> frame;
	frame.reserve(sizeof(net_len) + sizeof(nonce) + ciphertext_len);

	frame.insert(frame.end(),
				reinterpret_cast<uint8_t*>(&net_len),
				reinterpret_cast<uint8_t*>(&net_len) + sizeof(net_len));

	frame.insert(frame.end(), nonce, nonce + sizeof(nonce));
	frame.insert(frame.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

	on_message_ready(frame.data(), frame.size());
}

void CryptoInTransit::decrypt_message(uint8_t* ciphertext, size_t ciphertext_len, std::vector<uint8_t>& plaintext_out, const uint8_t* session_key, uint8_t* nonce)
{
    if (ciphertext_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        std::cerr << "Ciphertext length is less than authentication tag size" << std::endl;
        return;
    }
    
    // TODO - can just edit the caller provided plaintext buffer in-place
    std::vector<uint8_t> plaintext(ciphertext_len);
    unsigned long long plaintext_len;

    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(),
            &plaintext_len,
            nullptr,
            ciphertext,
            ciphertext_len,
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

void CryptoInTransit::encrypted_string_send(std::string message, DataSink on_message_ready, uint8_t* session_key)
{
    const uint8_t* data = reinterpret_cast<const uint8_t*>(message.data());
	size_t len = std::size(message);

    encrypt_message(data, len, on_message_ready, session_key);
}
