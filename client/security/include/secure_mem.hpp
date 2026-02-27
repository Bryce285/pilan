#include <sodium.h>
#include <stdexcept>

#pragma once

enum class KeyType {
	TRANSFER_AUTH,
	SESSION
};

struct SecureKey {
	uint8_t key_buf[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
	
	SecureKey(KeyType key_type) {
		if (key_type != KeyType::TRANSFER_AUTH) {
			throw std::runtime_error("Invalid constructor for given key type");
		}

		CryptoInTransit::load_tak(key_buf);

		if (sodium_mlock(&key_buf, crypto_aead_xchacha20poly1305_ietf_KEYBYTES) != 0) {
			throw std::runtime_error("sodium_mlock failed");
		}
	}

	// for session key	
    SecureKey(KeyType key_type, uint8_t tak[crypto_kdf_KEYBYTES]) {
		if (key_type != KeyType::SESSION) {
			throw std::runtime_error("Invalid constructor for given key type");
		}

		CryptoInTransit::derive_session_key(key_buf, tak);	
		
        if (sodium_mlock(&key_buf, crypto_aead_xchacha20poly1305_ietf_KEYBYTES) != 0) {
            throw std::runtime_error("sodium_mlock failed");
        }
    }

    ~SecureKey() {
        sodium_memzero(&key_buf, crypto_kdf_KEYBYTES);
        sodium_munlock(&key_buf, crypto_kdf_KEYBYTES);
    }
	
	// non-copyable
    SecureKey(const SecureKey&) = delete;
    SecureKey& operator=(const SecureKey&) = delete;

    // non-moveable
    SecureKey(SecureKey&&) = delete;
    SecureKey& operator=(SecureKey&&) = delete;
};
