#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <filesystem>
#include <fstream>

#include <sodium.h>

#include "client_storage_manager.hpp"
#include "socket_stream_writer.hpp"
#include "crypto.hpp"
#include "secure_mem.hpp"
#include "paths.hpp"

#pragma once

class Client
{
	public:
		explicit Client(SecureKey& tak) : TAK(tak) {}

		enum Command
		{
			DEFAULT,
			DOWNLOAD
		};

		struct ServerState
		{
			Command command = DEFAULT;
			
			std::string ifilename;
			size_t in_bytes_remaining = 0;

			bool connected = true;
			bool cur_srvr_msg_handled = false;

			std::vector<uint8_t> rx_buffer;

			ClientStorageManager::DownloadHandle cur_download_handle;
		};
        
		void handle_cmd(ServerState& state, std::string cmd, int sock);
		void handle_server_msg(ServerState& state, int sock);

	private:
		ClientStorageManager::StorageConfig config {
			.downloads_dir{PathMgr::downloads_dir},
			.tmp_dir{PathMgr::tmp_dir} 
		};

		ClientStorageManager storage_manager{config};
        CryptoInTransit crypto_transit;
       	
		SecureKey& TAK;
       	std::unique_ptr<SecureKey> session_key = std::make_unique<SecureKey>(KeyType::SESSION, TAK.key_buf);  

        bool recv_all(int sock, uint8_t* buf, size_t len);
        bool recv_encrypted_msg(int sock, uint8_t session_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], std::vector<uint8_t>& plaintext_out);

		void send_binary(std::filesystem::path filepath, int sock);
		void send_header(std::string header, int sock);
		void parse_msg(ServerState& state, size_t pos);
		void download_file(ServerState& state);
};
