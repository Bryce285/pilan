#include <sys/socket.h>   // socket(), bind(), listen(), accept(), send(), recv()
#include <netinet/in.h>   // sockaddr_in, INADDR_ANY, htons()
#include <arpa/inet.h>    // inet_addr() if needed
#include <unistd.h>       // close()

#include <openssl/crypto.h>

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

#include "server_storage_manager.hpp"
#include "socket_stream_writer.hpp"

#pragma once

class Server 
{
	public:
		void handle_client(int clientfd);
		
	private:
		// TODO - make sure auth actually times out after 30s
		const int AUTH_TIMEOUT = 30;
		
		ServerStorageManager::StorageConfig config {
			.root = "/home/bryce/projects/offlinePiFS/pi/data/", 
			.files_dir = "/home/bryce/projects/offlinePiFS/pi/data/files/", 
			.tmp_dir = "/home/bryce/projects/offlinePiFS/pi/data/tmp/", 
			.meta_dir = "/home/bryce/projects/offlinePiFS/pi/data/meta/",
			.max_file_size = 1000000000, // 1GB
			.max_total_size = 10000000000, // 10GB
			.read_only = false
		};

		ServerStorageManager storage_manager{config};

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
			std::string rx_buffer;
			int file_fd = -1;
		};

		void set_timeout(int clientfd);
		std::string load_auth_key();
		bool authenticate(int clientfd);
		
		bool upload_file(ClientState& state);
		void download_file(ClientState& state, int clientfd);
		void list_files(ClientState& state, int clientfd);
		void delete_file(ClientState& state, int clientfd);
		
		std::string parse_msg(ClientState& state, size_t pos, int clientfd);

		void client_loop(int clientfd);
};
