#include <sodium.h>

class CryptoInTransit
{
    public:
		using DataSink = std::function<void(const uint8_t* data, size_t len)>;

        void get_auth_tag(uint8_t* out_buf, uint8_t* server_nonce, uint8_t* tak);

        // TODO - key derivation function will be the same as what is implemented for the server
		void derive_session_key(uint8_t* key_buf, const uint8_t* tak);
		
		void encrypt_message(uint8_t* plaintext, DataSink on_message_ready, uint8_t* session_key);
		void decrypt_message(uint8_t* plaintext, DataSink on_message_ready, uint8_t* session_key);
};
