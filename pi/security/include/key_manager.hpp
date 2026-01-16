#include <sodium.h>
#include <array>

#pragma once

// TODO - the TAK should be manually shared between the server and client device, but we need to figure out a protocol for this (ex: USB, manually transfered config file, etc.)

class KeyManager
{
    public:
		const std::string FEK_CONTEXT = "file_encryption_v1";
		const std::string TAK_CONTEXT = "transport_auth_v1";

		// TODO - the key is only generated once on first boot, after that we need to load it
        uint8_t* gen_mdk();

		void derive_key(const uint8_t* mdk, uint8_t* key_out, size_t key_len, std::string context);
};

