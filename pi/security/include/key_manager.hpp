#include <sodium.h>
#include <array>
#include <fstream>
#include <filesystem>
#include <iostream>
#include "paths.hpp"
#include <vector>

#pragma once

class KeyManager
{
    public:
		const std::string FEK_CONTEXT = "file_encryption_v1";
		const std::string TAK_CONTEXT = "transport_auth_v1";

        static void load_or_gen_mdk(uint8_t key_buf[crypto_kdf_KEYBYTES]);

		static void derive_key(const uint8_t* mdk, uint8_t key_out[crypto_kdf_KEYBYTES], std::string context, uint64_t subkey_id, bool is_tak);

    private:
        constexpr static size_t SALT_SIZE = 16;
        constexpr static size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        constexpr static const char* HEADER = "MDK1";

		inline static std::filesystem::path MDK_PATH{PathMgr::mdk_path};
		
		static void print_tak(uint8_t tak[crypto_kdf_KEYBYTES]);
};
