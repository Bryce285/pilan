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

#pragma once

class Client
{
	public:	
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
			std::vector<uint8_t> rx_buffer;

			ClientStorageManager::DownloadHandle cur_download_handle;
		};
        
        Client();

		void handle_cmd(ServerState& state, std::string cmd, int sock);
		void handle_server_msg(ServerState& state, int sock);

	private:
		ClientStorageManager::StorageConfig config {
			.downloads_dir = "/home/bryce/projects/offlinePiFS/client/local_storage_test",
			.tmp_dir = "/home/bryce/projects/offlinePiFS/client/local_storage_test/tmp"
		};

		ClientStorageManager storage_manager{config};
        CryptoInTransit crypto_transit;
        
        uint8_t SESSION_KEY[crypto_kdf_KEYBYTES];

        bool recv_all(int sock, uint8_t* buf, size_t len);
        bool recv_encrypted_msg(int sock, const uint8_t session_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], std::vector<uint8_t>& plaintext_out);

		void send_binary(std::filesystem::path filepath, int sock);
		void send_header(std::string header, int sock);
		void parse_msg(ServerState& state, size_t pos);
		bool download_file(ServerState& state);
};
