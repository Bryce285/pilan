#include "crypto.hpp"

// TODO - ERROR HANDLING

void CryptoInTransit::get_auth_tag(uint8_t* out_buf, uint8_t* server_nonce, uint8_t* tak)
{
    crypto_auth_hmacsha256(out_buf, server_nonce, sizeof(server_nonce), tak);
}
