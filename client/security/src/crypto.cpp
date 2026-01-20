#include "crypto.hpp"

// TODO - ERROR HANDLING

void CryptoInTransit::get_auth_tag(uint8_t* out_buf, uint8_t* server_nonce, uint8_t* tak)
{
    // out_buf should be sized with the constant crypto_auth_hmacsha256_BYTES

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
	
	on_message_ready(htonl(ciphertext_len), sizeof(uint32_t));
	on_message_ready(nonce, sizeof(nonce));
	on_message_ready(ciphertext, CIPHERTEXT_LEN);
}

void CryptoInTransit::decrypt_message(uint8_t* ciphertext, std::vector<uint8_t>& plaintext_out, uint8_t* session_key, uint8_t* nonce)
{
	const size_t CIPHERTEXT_LEN = std::size(ciphertext);
	if (CIPHERTEXT_LEN < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
		std::cerr << "Ciphertext length is less than authentication tag size" << std::endl;
		return;
	}

	// TODO - can just edit the caller provided plaintext buffer in-place
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
	plaintext_out = plaintext;
}

void CryptoInTransit::encrypted_string_send(std::string message, DataSink on_message_ready, uint8_t* session_key)
{
	const uint8_t* data = reinterpret_cast<const uint8_t*>(message.data());
	encrypt_message(data, on_message_ready, session_key);
}
