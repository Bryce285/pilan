#include <string>
#include <chrono>
#include <unistd.h>

#pragma once

namespace ServerInit
{
	struct ClientConnection 
	{
		int fd;
		std::string ip;
		uint16_t port;
		std::chrono::steady_clock::time_point time;	
	};

  bool server_init();
}
