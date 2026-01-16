#include <sodium.h>

class CryptoInTransit
{
    public:
        void get_auth_tag(uint8_t* out_buf, uint8_t* server_nonce, uint8_t* tak);

        // TODO - key derivation function will be the same as what is implemented for the server
}
