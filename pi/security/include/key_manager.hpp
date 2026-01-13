#include <openssl/rand.h>
#include <openssl/err.h>
#include <array>

#pragma once

class KeyManager
{
    public:
        std::array<uint8_t, KEY_SIZE_BYTES> gen_mdk();

        // TODO - derive FEK and TAK

    private:
        const size_t KEY_SIZE_BYTES = 32;
};

