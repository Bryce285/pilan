#include "crypto.hpp"

// TODO - make sure that full error handling and secure failure are implemented

std::unique_ptr<SecureSecretstreamState> CryptoAtRest::file_encrypt_init(int fd_out, const uint8_t* fek)
{
    auto stream = std::make_unique<SecureSecretstreamState>();
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	
	for (int i = 0; i < 4; ++i)
    	printf("%02x ", fek[i]);
	printf("\n");


	// TODO - check for nullptr return and handle error when this function is called
    if (crypto_secretstream_xchacha20poly1305_init_push(
			&stream->state, 
			header, 
			fek) != 0) {
		return nullptr;
	}

    if (::write(fd_out, header, sizeof(header)) == -1) {
		throw std::runtime_error("Error in crypto.cpp:18: ::write() failed");
	}
	
    return stream;
}

void CryptoAtRest::encrypt_chunk(int fd_out, std::unique_ptr<SecureSecretstreamState>& stream, uint8_t* plaintext, size_t plaintext_len, const bool FINAL_CHUNK)
{
    // 1. Allocate ciphertext buffer
    std::vector<uint8_t> ciphertext(
        plaintext_len + crypto_secretstream_xchacha20poly1305_ABYTES
    );

    unsigned long long ciphertext_len = 0;

    const uint8_t tag = FINAL_CHUNK
        ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : 0;
	
	if (FINAL_CHUNK) {
		std::cout << "Final chunk" << std::endl;
	}

    // 2. Encrypt
    if (crypto_secretstream_xchacha20poly1305_push(
            &stream->state,
            ciphertext.data(),
            &ciphertext_len,
            plaintext,
            plaintext_len,
            nullptr,
            0,
            tag
        ) != 0) {

        sodium_memzero(plaintext, plaintext_len);
        throw std::runtime_error("Sodium error: push failed");
    }

    // 3. Write ciphertext length (framing)
    uint32_t clen_u32 = static_cast<uint32_t>(ciphertext_len);

    if (::write(fd_out, &clen_u32, sizeof(clen_u32)) != sizeof(clen_u32)) {
        sodium_memzero(plaintext, plaintext_len);
        throw std::runtime_error("write() failed (ciphertext length)");
    }

    // 4. Write ciphertext
    size_t total = 0;
    while (total < ciphertext_len) {
        ssize_t n = ::write(
            fd_out,
            ciphertext.data() + total,
            ciphertext_len - total
        );
        if (n <= 0) {
            sodium_memzero(plaintext, plaintext_len);
            throw std::runtime_error("write() failed (ciphertext)");
        }
        total += n;
    }
}

void CryptoAtRest::read_exact(int fd, void *buf, size_t len)
{
    uint8_t *p = static_cast<uint8_t *>(buf);
    size_t total = 0;

    while (total < len) {
        ssize_t n = ::read(fd, p + total, len - total);
        if (n == 0) {
            throw std::runtime_error("Unexpected EOF");
        }
        if (n < 0) {
            throw std::runtime_error("read() failed");
        }
        total += n;
    }
}

std::unique_ptr<SecureSecretstreamState> CryptoAtRest::file_decrypt_init(int fd_in, const uint8_t* fek)
{
    auto stream = std::make_unique<SecureSecretstreamState>();
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

	read_exact(fd_in, header, sizeof(header));
	
	for (int i = 0; i < 4; ++i)
    	printf("%02x ", fek[i]);
	printf("\n");


	// TODO - check for nullptr return anytime this function is called
    if (crypto_secretstream_xchacha20poly1305_init_pull(
			&stream->state, 
			header, 
			fek) != 0) {
        return nullptr; 
    }
    
    return stream;
}

void CryptoAtRest::decrypt_chunk(int fd_in, std::unique_ptr<SecureSecretstreamState>& stream, PlaintextSink on_chunk_ready, StreamWriter& writer)
{
    for (;;) {
        // 1. Read ciphertext length
        uint32_t clen_u32;
        read_exact(fd_in, &clen_u32, sizeof(clen_u32));

        const size_t ciphertext_len = clen_u32;

        if (ciphertext_len < crypto_secretstream_xchacha20poly1305_ABYTES) {
            throw std::runtime_error("Invalid ciphertext length");
        }

        // 2. Read ciphertext
        std::vector<uint8_t> ciphertext(ciphertext_len);
        read_exact(fd_in, ciphertext.data(), ciphertext_len);

        // 3. Prepare plaintext buffer
        std::vector<uint8_t> plaintext(
            ciphertext_len - crypto_secretstream_xchacha20poly1305_ABYTES
        );

        unsigned long long plaintext_len = 0;
        uint8_t tag = 0;
		
		std::cout << "Ciphertext len: " << ciphertext_len << std::endl;

        // 4. Decrypt
        if (crypto_secretstream_xchacha20poly1305_pull(
                &stream->state,
                plaintext.data(),
                &plaintext_len,
                &tag,
                ciphertext.data(),
                ciphertext_len,
                nullptr,
                0
            ) != 0) {

            sodium_memzero(plaintext.data(), plaintext.size());
            throw std::runtime_error("Sodium error: pull failed");
        }

        // 5. Emit plaintext
        on_chunk_ready(plaintext.data(), plaintext_len, writer);

        sodium_memzero(plaintext.data(), plaintext.size());

        // 6. Handle FINAL tag
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            break;
        }
    }
}

void CryptoInTransit::get_nonce(uint8_t out_buf[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
{
    randombytes_buf(out_buf, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
}

// TODO - make sure return value of this function is always checked
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
    if (crypto_kdf_derive_from_key(
            key_buf,
            crypto_kdf_KEYBYTES,
            1,
            "FILEXFER",
            tak
        ) != 0) {
		throw std::runtime_error("Key error: Failed to derive session key");
	}
}

// we recieve decrypted file data in chunks from the decrypt_chunk function, we then call this function on each decrypted chunk, and send the output to the client 
void CryptoInTransit::encrypt_message(uint8_t* plaintext, size_t plaintext_len, DataSink on_message_ready, uint8_t* session_key)
{
	uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    unsigned long long ciphertext_len;
    std::vector<uint8_t> ciphertext(plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES);

	if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(),
            &ciphertext_len,
            plaintext,
            plaintext_len,
            nullptr, 0,
            nullptr,
            nonce,
            session_key
        ) != 0) {
		sodium_memzero(plaintext, plaintext_len);
		throw std::runtime_error("Sodium encrypt error");
	}
    
    /*
     *  CHUNK MESSAGE PROTOCOL:
     *  [ciphertext length (network byte order]
     *  [nonce (24 bytes)]
     *  [ciphertext + auth tag]
     */
	
	if (ciphertext_len > UINT32_MAX) {
		sodium_memzero(plaintext, plaintext_len);
		throw std::runtime_error("Ciphertext chunk overflows 32 bit integer");
	}

	uint32_t net_len = htonl(static_cast<uint32_t>(ciphertext_len));
	
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

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(),
            &plaintext_len,
            nullptr,
            ciphertext,
            ciphertext_len,
            nullptr, 0,
            nonce,
            session_key
        ) != 0) {
        sodium_memzero(plaintext.data(), plaintext.size());
		throw std::runtime_error("Sodium decrypt error");
	}

    plaintext.resize(plaintext_len);
    plaintext_out = plaintext;
}

void CryptoInTransit::encrypted_string_send(std::string message, DataSink on_message_ready, uint8_t* session_key)
{
    uint8_t* data = reinterpret_cast<uint8_t*>(message.data());
	size_t len = std::size(message);

    encrypt_message(data, len, on_message_ready, session_key);
}
