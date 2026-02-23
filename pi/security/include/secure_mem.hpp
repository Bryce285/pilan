#include <sodium.h>
#include <stdexcept>

#pragma once

enum class KeyType {
	MASTER_DEVICE,
	TRANSFER_AUTH,
	FILE_ENCRYPT,
	SESSION
};

struct SecureSecretstreamState {
    crypto_secretstream_xchacha20poly1305_state state;

    SecureSecretstreamState() {
        if (sodium_mlock(&state, sizeof(state)) != 0) {
            throw std::runtime_error("sodium_mlock failed");
        }
    }

    ~SecureSecretstreamState() {
		sodium_memzero(&state, sizeof(state));
        sodium_munlock(&state, sizeof(state));
    }
	
	// non-copyable
    SecureSecretstreamState(const SecureSecretstreamState&) = delete;
    SecureSecretstreamState& operator=(const SecureSecretstreamState&) = delete;

    // non-moveable
    SecureSecretstreamState(SecureSecretstreamState&&) = delete;
    SecureSecretstreamState& operator=(SecureSecretstreamState&&) = delete;
};

struct SecureKey {
	uint8_t key_buf[crypto_kdf_KEYBYTES];
	
	// for mdk
    SecureKey(KeyType key_type) {
		if (key_type != KeyType::MASTER_DEVICE) {
			throw std::runtime_error("Invalid constructor for given key type");
		}

		KeyManager::load_or_gen_mdk(key_buf);

        if (sodium_mlock(&key_buf, crypto_kdf_KEYBYTES) != 0) {
            throw std::runtime_error("sodium_mlock failed");
        }
    }

	// for tak / fek
    SecureKey(KeyType key_type, uint8_t* mdk, std::string context, uint64_t subkey_id, bool is_tak) {
		if (key_type != KeyType::TRANSFER_AUTH && key_type != KeyType::FILE_ENCRYPT) {
			throw std::runtime_error("Invalid constructor for given key type");
		}

		KeyManager::derive_key(mdk, key_buf, context, subkey_id, is_tak);

        if (sodium_mlock(&key_buf, crypto_kdf_KEYBYTES) != 0) {
            throw std::runtime_error("sodium_mlock failed");
        }
    }
	
	// for session key
    SecureKey(KeyType key_type, uint8_t* tak) {
		if (key_type != KeyType::SESSION) {
			throw std::runtime_error("Invalid constructor for given key type");
		}
	
		crypto_kdf_derive_from_key(
				key_buf,
				crypto_kdf_KEYBYTES,
				1,
				"FILEXFER",
				tak
			);

        if (sodium_mlock(&key_buf, crypto_kdf_KEYBYTES) != 0) {
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
