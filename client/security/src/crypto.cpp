#include "crypto.hpp"

// TODO - ERROR HANDLING

void CryptoInTransit::get_auth_tag(uint8_t* out_buf, uint8_t* server_nonce, uint8_t* tak)
{
    crypto_auth_hmacsha256(out_buf, server_nonce, sizeof(server_nonce), tak);
}

void CryptoInTransit::derive_session_key(uint8_t* key_buf, const uint8_t* tak)
{
	crypto_kdf_derive_from_key(
			key_buf,
			sizeof(key_buf),
			1,
			"FILEXFER",
			tak
		);
}

void CryptoInTransit::encrypt_message(uint8_t* plaintext, DataSink on_message_ready, uint8_t* session_key)
{
	const size_t PLAINTEXT_LEN = std::size(plaintext);

	uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
	randombytes_buf(nonce, crypto_aead_xchacha20oly1305_ietf_NPUBBYTES);

	size_t ciphertext_len;
	uint8_t ciphertext[PLAINTEXT_LEN + crypto_aead_xchacha20poly1305_ietf_ABYTES];

	crypto_aead_xchacha20poly1305_ietf_encrypt(
			ciphertext,
			&ciphertext_len,
			plaintext,
			PLAINTEXT_LEN,
			nullptr, 0,
			nullptr,
			nonce,
			session_key
		);
	
	// TODO - sending the data to this function might not be necessary since we call encrypt message once for every chunk of TCP data we send
	on_message_ready(ciphertext, CIPHERTEXT_LEN);
}

void CryptoInTransit::decrypt_message(uint8_t* ciphertext, DataSink on_message_ready, uint8_t* session_key)
{
	const size_t CIPHERTEXT_LEN = std::size(ciphertext);
	if (CIPHERTEXT_LEN < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
		std::cerr << "Ciphertext length is less than authentication tag size" << std::endl;
		return;
	}

	std::vector<uint8_t> plaintext(CIPHERTEXT_LEN);
	size_t plaintext_len;

	int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
			plaintext.data(),
			&plaintext_len,
			nullptr,
			ciphertext,
			CIPHERTEXT_LEN,
			nullptr, 0,
			nonce,
			session_key
		);

	if (rc != 0) {
		// TODO - drop packet and disconnect client
		sodium_memzero(plaintext.data(), plaintext.size());
		std::cerr << "auth failed" << std::endl;
	}

	plaintext.resize(plaintext_len);
	on_message_ready(plaintext.data(), plaintext_len);
}
