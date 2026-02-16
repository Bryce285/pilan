#include "key_manager.hpp"

// lock memory of key_buf anytime this function is called
void KeyManager::load_or_gen_mdk(uint8_t key_buf[crypto_kdf_KEYBYTES])
{
	if (std::filesystem::exists(MDK_PATH)) {
    	auto size = std::filesystem::file_size(MDK_PATH);
    	if (size != crypto_kdf_KEYBYTES) {
        	throw std::runtime_error("MDK error: incorrect file size");
    	}

    	std::ifstream in_file(MDK_PATH, std::ios::binary);
    	if (!in_file) {
        	throw std::runtime_error("Failed to open MDK file");
    	}

    	in_file.read(reinterpret_cast<char*>(key_buf), crypto_kdf_KEYBYTES);

    	if (in_file.gcount() != crypto_kdf_KEYBYTES) {
        	throw std::runtime_error("Failed to read full MDK");
    	}
	}
	else {

    	crypto_kdf_keygen(key_buf);

    	std::ofstream out_file(MDK_PATH, std::ios::binary);
		out_file.exceptions(std::ios::failbit | std::ios::badbit);
    	if (!out_file) {
        	throw std::runtime_error("Failed to create MDK file");
    	}
		
    	out_file.write(reinterpret_cast<const char*>(key_buf), crypto_kdf_KEYBYTES);

    	if (!out_file) {
        	throw std::runtime_error("Failed to write MDK");
    	}

    	out_file.flush();
	}
}

void KeyManager::print_tak(uint8_t tak[crypto_kdf_KEYBYTES])
{
    std::string border = 	"================================================================\n";
    std::string label = 	"           Transfer Authentication Key (DO NOT SHARE)\n";

    char hex[crypto_kdf_KEYBYTES * 2 + 1];

    sodium_bin2hex(
        hex,
        sizeof(hex),
        tak,
        crypto_kdf_KEYBYTES
    );

    std::cout << border
              << label
              << border
              << hex << "\n"
              << border;
}

// lock memory of key_out anytime this function is called
void KeyManager::derive_key(const uint8_t* mdk, uint8_t key_out[crypto_kdf_KEYBYTES], std::string context, uint64_t subkey_id, bool is_tak)
{
	if (crypto_kdf_derive_from_key(
			key_out, 
			crypto_kdf_KEYBYTES, 
			subkey_id, 
			context.data(), 
			mdk) != 0) {
		throw std::runtime_error("Sodium error: Failed to derive key");
	}
	
	if (is_tak) print_tak(key_out);
}
