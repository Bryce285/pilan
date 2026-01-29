#include "key_manager.hpp"

void KeyManager::load_or_gen_mdk(uint8_t key_buf[crypto_kdf_KEYBYTES])
{
    if (std::filesystem::exists(MDK_PATH)) {
        std::ifstream in_file(MDK_PATH, std::ios::binary);
        if (!in_file) {
            throw std::runtime_error("File error: Failed to open " + MDK_PATH.string());
        }
        
        std::streampos size = in_file.tellg();
        in_file.seekg(0, std::ios::beg);

        if (size != crypto_kdf_KEYBYTES) {
            throw std::runtime_error("MDK error: master device key does not have expected size");
        }

        in_file.read(reinterpret_cast<char*>(key_buf), crypto_kdf_KEYBYTES);

        std::streamsize bytes_read = in_file.gcount();
        if (bytes_read != crypto_kdf_KEYBYTES) {
            throw std::runtime_error("MDK error: Wrong number of bytes read");
        }

        in_file.close();
    }
    else {
        crypto_kdf_keygen(key_buf);
		// TODO - write mdk to path
    }
}

void KeyManager::TMP_write_tak(uint8_t* tak)
{
	std::filesystem::path tak_path = "/home/bryce/projects/offlinePiFS/client/tak_tmp_path/tak.txt";

	std::ofstream out_file(tak_path, std::ios::binary);
	if (!out_file) {
    	throw std::runtime_error("Failed to create/write tak file");
	}

	out_file.write(reinterpret_cast<const char*>(tak), crypto_kdf_KEYBYTES); 
	out_file.close();
}

void KeyManager::derive_key(const uint8_t* mdk, uint8_t* key_out, std::string context, uint64_t subkey_id)
{
    // TODO - error handling here
	crypto_kdf_derive_from_key(key_out, crypto_kdf_KEYBYTES, subkey_id, context.data(), mdk);

	TMP_write_tak(key_out);
}
