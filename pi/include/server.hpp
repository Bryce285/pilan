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
		Server();
		static void handle_client(int clientfd);
		
	private:
		// TODO - make sure auth actually times out after 30s
		const int AUTH_TIMEOUT = 30;
		
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

		static void set_timeout(int clientfd);
		static std::string load_auth_key();
		static bool authenticate(int clientfd);
		
		static bool upload_file(ClientState& state);
		static void download_file(ClientState& state, int clientfd);
		static void list_files(ClientState& state, int clientfd);
		static void delete_file(ClientState& state, int clientfd);
		
		static std::string parse_msg(ClientState& state, size_t pos, int clientfd);

		static void client_loop(int clientfd);
};
