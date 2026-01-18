#include "key_manager.hpp"

uint8_t* KeyManager::load_or_gen_mdk()
{
    uint8_t key_buf[crypto_kdf_KEYBYTES];
    
    if (std::filesystem::exists(MDK_PATH)) {
        std::ifstream in_file(MDK_PATH, std::ios::binary);
        if (!in_file) {
            throw std::runtime_error("File error: failed to open " + MDK_PATH.string());
        }
        
        std::streampos size = in_file.tellg();
        in_file.seekg(0, std::ios::beg);

        if (size != crypto_kdf_KEYBYTES) {
            throw std::runtime_error("MDK error: master device key does not have expected size");
        }

        in_file.read(key_buf, crypto_kdf_KEYBYTES);
        in_file.close();
    }
    else {
        crypto_kdf_keygen(key_buf);
    }

    return key_buf;
}

void KeyManager::derive_key(const uint8_t* mdk, uint8_t* key_out, std::string context, uint64_t subkey_id)
{
    // TODO - error handling here
	crypto_kdf_derive_from_key(key_out, crypto_kdf_KEYBYTES, subkey_id, context, mdk);
}
