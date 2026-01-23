#include <sodium.h>

class CryptoInTransit
{
    public:
		using DataSink = std::function<void(const uint8_t* data, size_t len)>;
        
        uint8_t* load_tak();
        void get_auth_tag(uint8_t* out_buf, uint8_t* server_nonce, uint8_t* tak);
		void derive_session_key(uint8_t* key_buf, const uint8_t* tak);
		
		void encrypt_message(uint8_t* plaintext, DataSink on_message_ready, uint8_t* session_key);
		void decrypt_message(uint8_t* ciphertext, std::vector<uint8_t>& plaintext_out, uint8_t* session_key, uint8_t* nonce);
		
		void encrypted_string_send(std::string message, DataSink on_message_ready, uint8_t* session_key);

    private:

        // TODO - TAK storage as plaintext is for testing only, should be replaced by some kind of config file
        const std::filesystem::path TAK_PATH = "/home/bryce/projects/PiFileshare/PiFileshare/client/tak_tmp_path/tak.txt";
};
