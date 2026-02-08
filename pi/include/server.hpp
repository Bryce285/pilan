#include <sys/socket.h>   // socket(), bind(), listen(), accept(), send(), recv()
#include <netinet/in.h>   // sockaddr_in, INADDR_ANY, htons()
#include <arpa/inet.h>    // inet_addr() if needed
#include <unistd.h>       // close()

#include <sodium.h>

#include <vector>
#include <chrono>
#include <string>
#include <iostream>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <csignal>
#include <cstring>
#include <algorithm>

#include "server_storage_manager.hpp"
#include "socket_stream_writer.hpp"
#include "key_manager.hpp"
#include "crypto.hpp"
#include "secure_mem.hpp"

#pragma once

class Server 
{
	public:
		void handle_client(int clientfd);

	private:
		// TODO - make sure auth actually times out after 30s
		const int AUTH_TIMEOUT = 30;

        KeyManager key_manager;
        std::unique_ptr<SecureKey> MDK = std::make_unique<SecureKey>(KeyType::MASTER_DEVICE);

        std::string fek_context = "file_encryption_v1";
        uint64_t fek_subkey_id = 1;
        std::unique_ptr<SecureKey> FEK = std::make_unique<SecureKey>(KeyType::FILE_ENCRYPT, MDK->key_buf, fek_context, fek_subkey_id, false);

        std::string tak_context = "transfer_auth_v1";
        uint64_t tak_subkey_id = 2; 
        std::unique_ptr<SecureKey> TAK = std::make_unique<SecureKey>(KeyType::TRANSFER_AUTH, MDK->key_buf, tak_context, tak_subkey_id, true);
 
        std::unique_ptr<SecureKey> SESSION_KEY;
		
		ServerStorageManager::StorageConfig config {
			.root = "/home/bryce/projects/offlinePiFS/pi/data/", 
			.files_dir = "/home/bryce/projects/offlinePiFS/pi/data/files/", 
			.tmp_dir = "/home/bryce/projects/offlinePiFS/pi/data/tmp/", 
			.meta_dir = "/home/bryce/projects/offlinePiFS/pi/data/meta/",
			.max_file_size = 1000000000, // 1GB
			.max_total_size = 10000000000, // 10GB
			.read_only = false
		};
		
		ServerStorageManager storage_manager{config, *FEK};

		// TODO - move this inside the state struct
		ServerStorageManager::UploadHandle cur_upload_handle;

		enum Command 
		{
			DEFAULT,
			LIST,
			UPLOAD,
			DOWNLOAD,
			DELETE
		};

		struct ClientState 
		{
			Command command = DEFAULT;

			std::string ifilename;
			size_t in_bytes_remaining = 0;

			std::string ofilename;
			size_t out_bytes_remaining = 0;

			std::string file_to_delete;

			bool connected = true;
            std::vector<uint8_t> rx_buffer;
			int file_fd = -1;
		};

		void set_timeout(int clientfd);
		bool authenticate(int clientfd);
        
        bool recv_all(int sock, uint8_t* buf, size_t len);
        bool recv_encrypted_msg(int sock, const uint8_t session_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], std::vector<uint8_t>& plaintext_out);

		bool upload_file(ClientState& state);
		void download_file(ClientState& state, int clientfd);
		void list_files(ClientState& state, int clientfd);
		void delete_file(ClientState& state, int clientfd);
		
		std::string parse_msg(ClientState& state, size_t pos);

		void client_loop(int clientfd);
};
