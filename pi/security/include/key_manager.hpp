#include <sodium.h>
#include <array>
#include <fstream>
#include <filesystem>

#pragma once

// TODO - the TAK should be manually shared between the server and client device, but we need to figure out a protocol for this (ex: USB, manually transfered config file, etc.)

class KeyManager
{
    public:
		const std::string FEK_CONTEXT = "file_encryption_v1";
		const std::string TAK_CONTEXT = "transport_auth_v1";

        static void load_or_gen_mdk(uint8_t key_buf[crypto_kdf_KEYBYTES]);

		static void derive_key(const uint8_t* mdk, uint8_t* key_out, std::string context, uint64_t subkey_id, bool is_tak);

    private:
        inline static const std::filesystem::path MDK_PATH = "/home/bryce/projects/offlinePiFS/pi/mdk_tmp_path/mdk.txt";
		
		// TODO - this is a temp function for testing
		static void TMP_write_tak(uint8_t* tak);
};
