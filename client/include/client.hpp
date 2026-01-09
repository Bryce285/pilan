#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <filesystem>
#include <fstream>

#include "client_storage_manager.hpp"
#include "socket_stream_writer.hpp"

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

			ClientStorageManager::DownloadHandle cur_download_handle;
		};

		Client();

		static void handle_cmd(ServerState& state, std::string cmd, int sock);
		static void handle_server_msg(ServerState& state, int sock);

	private:
		static void send_binary(std::filesystem::path filepath, int sock);
		static void send_header(std::string header, int sock);
		static void parse_msg(ServerState& state, size_t pos);
		static bool download_file(ServerState& state);
};
