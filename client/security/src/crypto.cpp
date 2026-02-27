#include "crypto.hpp"

void CryptoInTransit::write_tak(const std::string& tak)
{
	if (tak.size() % 2 != 0) {
        throw std::runtime_error("Invalid hex string length");
    }

    std::vector<uint8_t> binary(tak.size() / 2);

    size_t bin_len = 0;

    if (sodium_hex2bin(
            binary.data(),
            binary.size(),
            tak.c_str(),
            tak.size(),
            nullptr,
            &bin_len,
            nullptr) != 0) {

        throw std::runtime_error("Invalid hex string");
    }
	
	encrypt_tak(binary.data());
	sodium_memzero(binary.data(), binary.size());
}

/*
	TODO - there are a lot of instances where the wrong KEYBYTES constant is used.
	It works because crypto_kdf_KEYBYTES and crypto_aead_xchacha20poly1305_ietf_KEYBYTES
	are the same size, but for clarity the correct constant should be used.
*/
// mlock key_buf anytime this function is used
void CryptoInTransit::load_tak(uint8_t key_buf[crypto_kdf_KEYBYTES])
{
    if (std::filesystem::exists(TAK_PATH)) {
    	decrypt_tak(key_buf);
	}
	else {
        throw std::runtime_error("TAK error: Transfer authentication key not found");
    }
}

void CryptoInTransit::get_auth_tag(uint8_t* out_buf, uint8_t* server_nonce, uint8_t tak[crypto_kdf_KEYBYTES])
{
    // out_buf should be sized with the constant crypto_auth_hmacsha256_BYTES
	
	if (crypto_auth_hmacsha256(
			out_buf, 
			server_nonce, 
			sizeof(server_nonce), 
			tak) != 0) {
		throw std::runtime_error("Sodium error: failed to generate auth tag");
	}
}

// mlock key_buf anytime this function is used
void CryptoInTransit::derive_session_key(uint8_t* key_buf, uint8_t tak[crypto_kdf_KEYBYTES])
{
	if (crypto_kdf_derive_from_key(
			key_buf,
			crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
			1,
			"FILEXFER",
			tak
		) != 0) {
		throw std::runtime_error("Sodium error: Failed to derive key");
	}
}

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

void CryptoInTransit::decrypt_message(uint8_t* ciphertext, size_t ciphertext_len, std::vector<uint8_t>& plaintext_out, uint8_t* session_key, uint8_t* nonce)
{
	if (ciphertext_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
		throw std::runtime_error("Ciphertext length is less than authentication tag size");	
	}

	plaintext_out.resize(ciphertext_len);
	unsigned long long plaintext_len;

	if (crypto_aead_xchacha20poly1305_ietf_decrypt(
			plaintext_out.data(),
			&plaintext_len,
			nullptr,
			ciphertext,
			ciphertext_len,
			nullptr, 0,
			nonce,
			session_key
		) != 0) {
		sodium_memzero(plaintext_out.data(), plaintext_out.size());
		throw std::runtime_error("Sodium decrypt error");
	}

	plaintext_out.resize(plaintext_len);
}

void CryptoInTransit::encrypted_string_send(std::string message, DataSink on_message_ready, uint8_t* session_key)
{
	uint8_t* data = reinterpret_cast<uint8_t*>(message.data());
	size_t len = std::size(message);
	
	try {
		encrypt_message(data, len, on_message_ready, session_key);
	}
	catch (const std::exception& e) {
		std::cerr << "Failed to send encrypted string: " << e.what() << std::endl;
	}
}

void CryptoInTransit::encrypt_tak(uint8_t key_buf[crypto_aead_xchacha20poly1305_ietf_KEYBYTES])
{
	uint8_t salt[SALT_SIZE];
	uint8_t nonce[NONCE_SIZE];
	randombytes_buf(salt, sizeof(salt));
	randombytes_buf(nonce, sizeof(nonce));

	std::string passphrase, passphrase_confirm;
	std::cout << "Enter a passphrase to protect your transfer authentication key. This can be the same or different as your master key passphrase: ";
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

	std::ofstream out_file(TAK_PATH, std::ios::binary);
	out_file.exceptions(std::ios::failbit | std::ios::badbit);
	if (!out_file) {
		throw std::runtime_error("Failed to create TAK file");
	}

	out_file.write(HEADER, 4);
	out_file.write(reinterpret_cast<const char*>(salt), SALT_SIZE);
	out_file.write(reinterpret_cast<const char*>(nonce), NONCE_SIZE);
	out_file.write(reinterpret_cast<const char*>(enc_key.data()), enc_key.size());
	out_file.flush();

	if (!out_file) {
		throw std::runtime_error("Failed to write encrypted TAK");
	}
}

void CryptoInTransit::decrypt_tak(uint8_t out_buf[crypto_aead_xchacha20poly1305_ietf_KEYBYTES])
{
	std::ifstream in_file(TAK_PATH, std::ios::binary);
	if (!in_file) {
		throw std::runtime_error("Failed to open TAK file");
	}

	char header[4];
	in_file.read(header, 4);
	if (std::string(header, 4) != HEADER) {
		throw std::runtime_error("Invalid TAK header");
	}

	uint8_t salt[SALT_SIZE];
	in_file.read(reinterpret_cast<char*>(salt), SALT_SIZE);

	uint8_t nonce[NONCE_SIZE];
	in_file.read(reinterpret_cast<char*>(nonce), NONCE_SIZE);

	std::vector<uint8_t> enc_key(crypto_kdf_KEYBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES);
	in_file.read(reinterpret_cast<char*>(enc_key.data()), enc_key.size());
	if (in_file.gcount() != enc_key.size()) {
		throw std::runtime_error("Incomplete TAK file");
	}

	std::string passphrase;
	std::cout << "Enter passphrase to unlock transfer authentication key: ";
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
				out_buf, nullptr,
				nullptr,
				enc_key.data(), enc_key.size(),
				nullptr, 0,
				nonce, kdf_key) != 0) {
		throw std::runtime_error("Failed to decrypt TAK: incorrect passphrase or corrupted file");
	}
}
