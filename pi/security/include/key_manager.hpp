#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <array>

#pragma once

class KeyManager
{
    public:
		const std::string FEK_SALT = "filebox_fek";
		const std::string FEK_INFO = "file_encryption_v1";

		const std::string TAK_SALT = "filebox_tak";
		const std::string TAK_INFO = "transport_auth_v1";

		// TODO - the key is only generated once on first boot, after that we need to load it
        std::array<uint8_t, MDK_SIZE_BYTES> gen_mdk();

		bool derive_key(const uint8_t* mdk, size_t mdk_len, uint8_t* key_out, size_t key_len, std::string salt, std::string info);

    private:
        const size_t MDK_SIZE_BYTES = 32;
};

