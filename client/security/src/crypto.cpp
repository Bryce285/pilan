#include "crypto.hpp"

// mlock key_buf anytime this function is used
void CryptoInTransit::load_tak(uint8_t key_buf[crypto_kdf_KEYBYTES])
{
    if (std::filesystem::exists(TAK_PATH)) {
        std::ifstream in_file(TAK_PATH, std::ios::binary);
        if (!in_file) {
            throw std::runtime_error("File error: Failed to open " + TAK_PATH.string());
        }
       
	   	auto size = std::filesystem::file_size(TAK_PATH); 

		if (size != crypto_kdf_KEYBYTES) {
            throw std::runtime_error("TAK error: Transfer authentication key does not have expected size");
        }
        
        in_file.read(reinterpret_cast<char*>(key_buf), crypto_kdf_KEYBYTES);
		if (in_file.fail() || in_file.bad()) {
			throw std::runtime_error("File error: Failed to read transfer authentication key from disk");
		}

        std::streamsize bytes_read = in_file.gcount();
        if (bytes_read != crypto_kdf_KEYBYTES) {
            throw std::runtime_error("TAK error: Wrong number of bytes read");
        }

        in_file.close();
    }
    else {
        throw std::runtime_error("TAK error: Transfer authentication key not found");
    }
}

void CryptoInTransit::get_auth_tag(uint8_t* out_buf, uint8_t* server_nonce)
{
    // out_buf should be sized with the constant crypto_auth_hmacsha256_BYTES
    
	uint8_t tak[crypto_kdf_KEYBYTES];
	load_tak(tak); // don't need to mlock tak here because it only exists for this function call
    
	if (crypto_auth_hmacsha256(
			out_buf, 
			server_nonce, 
			sizeof(server_nonce), 
			tak) != 0) {
		throw std::runtime_error("Sodium error: failed to generate auth tag");
	}
}

// mlock key_buf anytime this function is used
void CryptoInTransit::derive_session_key(uint8_t* key_buf)
{
	uint8_t tak[crypto_kdf_KEYBYTES];
    load_tak(tak); // don't need to mlock tak here because it only exists for this function call

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
