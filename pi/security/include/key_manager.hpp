#include <sodium.h>
#include <array>
#include <fstream>
#include <filesystem>
#include <iostream>
#include "paths.hpp"

#pragma once

class KeyManager
{
    public:
		const std::string FEK_CONTEXT = "file_encryption_v1";
		const std::string TAK_CONTEXT = "transport_auth_v1";

        static void load_or_gen_mdk(uint8_t key_buf[crypto_kdf_KEYBYTES]);

		static void derive_key(const uint8_t* mdk, uint8_t key_out[crypto_kdf_KEYBYTES], std::string context, uint64_t subkey_id, bool is_tak);

    private:
#if DEVPATHS
		inline static std::filesystem::path MDK_PATH{DevPaths::mdk_path};
		inline static std::filesystem::path TAK_PATH{DevPaths::tak_path};
#else
		inline static std::filesystem::path MDK_PATH{ProdPaths::mdk_path};
		inline static std::filesystem::path TAK_PATH{ProdPaths::tak_path};
#endif
		
		static void print_tak(uint8_t tak[crypto_kdf_KEYBYTES]);
		static void write_tak(uint8_t tak[crypto_kdf_KEYBYTES]);
};
