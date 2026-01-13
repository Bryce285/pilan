#include "key_manager.hpp"

std::array<uint8_t, KeyManager::KEY_SIZE_BYTES> KeyManager::gen_mdk()
{
    std::array<uint8_t, KEY_SIZE_BYTES> key{};

    if (RAND_bytes(key, KEY_SIZE_BYTES) != 1) {
        std::cerr << "Failed to generate random bytes" << std::endl;
        ERR_print_errors_fp(stderr);
    }

    return key;
}
