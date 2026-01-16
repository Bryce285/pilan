#include "key_manager.hpp"

uint8_t* KeyManager::gen_mdk()
{
    uint8_t key_buf[crypto_kdf_KEYBYTES];
    crypto_kdf_keygen(key_buf);

    return key_buf;
}

void KeyManager::derive_key(const uint8_t* mdk, uint8_t* key_out, size_t key_len, std::string context, uint64_t subkey_id)
{
	crypto_kdf_derive_from_key(key_out, key_len, subkey_id, context, mdk);
}
