#include "key_manager.hpp"

std::array<uint8_t, KeyManager::MDK_SIZE_BYTES> KeyManager::gen_mdk()
{
    std::array<uint8_t, MDK_SIZE_BYTES> key{};

    if (RAND_bytes(key, MDK_SIZE_BYTES) != 1) {
        std::cerr << "Failed to generate random bytes" << std::endl;
        ERR_print_errors_fp(stderr);
    }

    return key;
}

bool KeyManager::derive_key (const uint8_t* mdk, size_t mdk_len, uint8_t* key_out, size_t key_len, std::string salt, std::string info)
{
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
	if (!pctx) return false;

	if (EVP_PKEY_derive_init(pctx) <= 0) return false;
	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) return false;

	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, 
		reinterpret_cast<const uint8_t*>(salt), 
		strlen("filebox_fek")) <= 0) return false;

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, mdk, mkd_len) <= 0) return false;
	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, 
		reinterpret_cast<const uint8_t*>(info), 
		strlen("file_encryption_v1")) <= 0) return false;

	size_t len = key_len;
	if (EVP_PKEY_derive(pctx, key_out, &len) <= 0) return false;

	EVP_PKEY_CTX_free(pctx);
	return true;
}
