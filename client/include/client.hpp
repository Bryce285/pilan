#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <filesystem>
#include <fstream>

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
			std::string rx_buffer;
		};

		static void handle_cmd(ServerState& state, std::string cmd, int sock);
		static void handle_server_msg(ServerState& state, int sock);

	private:
		static void send_binary(std::filesystem::path filepath, int sock);
		static void send_header(std::string header, int sock);
		static void parse_msg(ServerState& state, size_t pos);
		
		template <size_t N>
		static bool download_file(ServerState& state, const char (&buf)[N], ssize_t n, int sock)
		{
			bool done = false;

			std::string ifilename = state.ifilename + ".tmp";
			std::filesystem::path ifilepath = ifilename;

			if (!std::filesystem::exists(ifilepath)) {
				std::ofstream tmp(ifilename);
			}

			std::ofstream outFile(ifilename, std::ios::binary | std::ios::app);
			if (!outFile.is_open()) {
				std::cerr << "Failed to open " << ifilename << " for download." << std::endl;
			}

			if (state.in_bytes_remaining > 0) {
				const char* constPtr = buf;
				outFile.write(constPtr, n);
				state.in_bytes_remaining -= n;
				outFile.close();
				return done;
			}

			std::filesystem::path permPath = state.ifilename;
			std::filesystem::rename(ifilepath, permPath);
			// TODO - handle rename error

			state.command = DEFAULT;
			state.connected = false;
			done = true;
			return done;
		}
};
