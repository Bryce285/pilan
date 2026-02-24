#include "key_manager.hpp"

// lock memory of key_buf anytime this function is called
void KeyManager::load_or_gen_mdk(uint8_t key_buf[crypto_kdf_KEYBYTES])
{
	if (std::filesystem::exists(MDK_PATH)) {
    	std::ifstream in_file(MDK_PATH, std::ios::binary);
    	if (!in_file) {
        	throw std::runtime_error("Failed to open MDK file");
    	}
        
        char header[4];
        in_file.read(header, 4);
        if (std::string(header, 4) != HEADER) {
            throw std::runtime_error("Invalid MDK header");
        }
        
        uint8_t salt[SALT_SIZE];
        in_file.read(reinterpret_cast<char*>(salt), SALT_SIZE);

        uint8_t nonce[NONCE_SIZE];
        in_file.read(reinterpret_cast<char*>(nonce), NONCE_SIZE);
        
        std::vector<uint8_t> enc_key(crypto_kdf_KEYBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        in_file.read(reinterpret_cast<char*>(enc_key.data()), enc_key.size());
        if (in_file.gcount() != enc_key.size()) {
            throw std::runtime_error("Incomplete MDK file");
        }
        
        std::string passphrase;
        std::cout << "Enter passphrase to unlock master key: ";
        std::getline(std::cin, passphrase);

        uint8_t kdf_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
        if (crypto_pwhash(kdf_key, sizeof(kdf_key),
                            passphrase.c_str(), passphrase.size(),
                            salt,
                            crypto_pwhash_OPSLIMIT_MODERATE,
                            crypto_pwhash_MEMLIMIT_MODERATE,
                            crypto_pwhash_ALG_ARGON2ID13) != 0) {
            throw std::runtime_error("KDF derivation failed");
        }

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                    key_buf, nullptr,
                    nullptr,
                    enc_key.data(), enc_key.size(),
                    nullptr, 0,
                    nonce, kdf_key) != 0) {
            throw std::runtime_error("Failed to decrypt MDK: incorrect passphrase or corrupted file");
        }
	}
	else {
    	crypto_kdf_keygen(key_buf);

        uint8_t salt[SALT_SIZE];
        uint8_t nonce[NONCE_SIZE];
        randombytes_buf(salt, sizeof(salt));
        randombytes_buf(nonce, sizeof(nonce));

        std::string passphrase, passphrase_confirm;
        std::cout << "Enter passphrase to protect master key (save this somewhere safe, if you lose this passphrase you will not be able to decrypt any of your files): ";
        std::getline(std::cin, passphrase);
        std::cout << "Confirm passphrase: ";
        std::getline(std::cin, passphrase_confirm);
        if (passphrase != passphrase_confirm) {
            throw std::runtime_error("Passphrase mismatch");
        }

        uint8_t kdf_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
        if (crypto_pwhash(kdf_key, sizeof(kdf_key),
                            passphrase.c_str(), passphrase.size(),
                            salt,
                            crypto_pwhash_OPSLIMIT_MODERATE,
                            crypto_pwhash_MEMLIMIT_MODERATE,
                            crypto_pwhash_ALG_ARGON2ID13) != 0) {
            throw std::runtime_error("KDF derivation failed");
        }

        std::vector<uint8_t> enc_key(crypto_kdf_KEYBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long enc_len;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
                enc_key.data(), &enc_len,
                key_buf, crypto_kdf_KEYBYTES,
                nullptr, 0,
                nullptr,
                nonce,
                kdf_key
        );

    	std::ofstream out_file(MDK_PATH, std::ios::binary);
		out_file.exceptions(std::ios::failbit | std::ios::badbit);
    	if (!out_file) {
        	throw std::runtime_error("Failed to create MDK file");
    	}
		
        out_file.write(HEADER, 4);
        out_file.write(reinterpret_cast<const char*>(salt), SALT_SIZE);
        out_file.write(reinterpret_cast<const char*>(nonce), NONCE_SIZE);
        out_file.write(reinterpret_cast<const char*>(enc_key.data()), enc_key.size());
        out_file.flush();

    	if (!out_file) {
        	throw std::runtime_error("Failed to write encrypted MDK");
    	}
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
	
	if (is_tak) {
		print_tak(key_out);
	}
}
