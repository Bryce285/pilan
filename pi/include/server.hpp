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

#pragma once

class Server 
{
	public:
		void handle_client(int clientfd);
		
	private:
		// TODO - make sure auth actually times out after 30s
		const int AUTH_TIMEOUT = 30;

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
		bool download_file(ClientState& state, int clientfd);
		void list_files(ClientState& state, int clientfd);
		void delete_file(ClientState& state);
		
		std::string parse_msg(ClientState& state, size_t pos);

		void client_loop(int clientfd);
};
