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
		static void handle_client(int clientfd);
		
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

		static void set_timeout(int clientfd);
		static std::string load_auth_key();
		static bool authenticate(int clientfd);
		
		// TODO - don't write metadata sent in header to the actual file
		template <size_t N>
		static bool upload_file(ClientState& state, const char (&buf)[N], ssize_t n)
		{
			std::cout << "Entered upload function" << std::endl;

			bool done = false;

			std::string ifilename = state.ifilename + ".tmp";
			std::filesystem::path ifilepath = "/home/bryce/projects/offlinePiFS/pi/pi_storage_test/" + ifilename;

			// check if temp file for ofilename exists, create it if not
			if (!std::filesystem::exists(ifilepath)) {
				std::ofstream tmp(ifilepath);
			}
				
			std::ofstream outFile(ifilepath, std::ios::binary | std::ios::app);
			if (!outFile.is_open()) {
				std::cerr << "Failed to open " << ifilepath.string() << " for upload." << std::endl;
			}

			// if bytes_remaining > 0 write binary data from recv to file
			if (n > 0 && state.in_bytes_remaining > 0) {
				const char* constPtr = buf;
				outFile.write(constPtr, n);
				state.in_bytes_remaining -= n;
				outFile.close();
				return done;
			}

			// if there are no bytes left to write, make temp file permanent
			std::filesystem::path permPath = "/home/bryce/projects/offlinePiFS/pi/pi_storage_test/" + state.ifilename;
			std::filesystem::rename(ifilepath, permPath);
			//TODO - handle rename error

			state.command = DEFAULT;
			state.connected = false;
			done = true;
			return done;
		}	

		static bool download_file(ClientState& state, int clientfd);
		static void list_files(ClientState& state, int clientfd);
		static void delete_file(ClientState& state, int clientfd);
		
		static std::string parse_msg(ClientState& state, size_t pos, int clientfd);

		static void client_loop(int clientfd);
};
