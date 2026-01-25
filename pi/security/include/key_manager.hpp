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

        void load_or_gen_mdk(uint8_t key_buf[crypto_kdf_KEYBYTES]);

		void derive_key(const uint8_t* mdk, uint8_t* key_out, std::string context, uint64_t subkey_id);

    private:
        const std::filesystem::path MDK_PATH = "/home/bryce/projects/PiFileshare/PiFileshare/pi/mdk_tmp_path/mdk.txt";
};

