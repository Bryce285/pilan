#include <sodium.h>
#include <stdexcept>

#pragma once

/*	TODO
*	The architecture here can be cleaned up. Some of these structs can probably
*	be combined and just have multiple constructors. Using these structs also makes
* 	some of the functions implemented in the CryptoInTransit / CryptoAtRest API
* 	obselete so those functions can probably be removed. If we can get this file down
*	to one or two structs than we might want to put them in the crypto header for a 
*	cleaner API.
*/

struct SecureKey {
	uint8_t key_buf[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
	
	// for session key
    SecureKey() {
		CryptoInTransit::derive_session_key(key_buf);	
		
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
