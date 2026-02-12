#include <sys/socket.h>   // socket(), bind(), listen(), accept(), send(), recv()
#include <netinet/in.h>   // sockaddr_in, INADDR_ANY, htons()
#include <arpa/inet.h>    // inet_addr() if needed
#include <unistd.h>       // close()
#include <fcntl.h>

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

#include <sodium.h>

#include "server.hpp"
#include "key_manager.hpp"
#include "logger.hpp"

Logger logger;
Server server(logger);

void log_exit()
{
	logger.log_event(Logger::LogEvent::SERVICE_STOP);
}

// for logging connections
struct ClientConnection 
{
	int fd;
	std::string ip;
	uint16_t port;
	std::chrono::steady_clock::time_point time;	
};

int main()
{
	logger.log_event(Logger::LogEvent::SERVICE_START);

	std::atexit(log_exit);

    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        exit(1);
    }

	bool quit = false;

	// create a socket
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("Failed to create socket.");
		exit(1);
	}

	// Bind the ip address and port to a socket
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8080);
	addr.sin_addr.s_addr = INADDR_ANY;

	int opt = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	signal(SIGPIPE, SIG_IGN);

	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Failed to bind socket.");
		exit(1);
	}

	// tell sys/socket the socket is for listening	
	if (listen(sockfd, 8) < 0) {
		perror("Listening failed.");
		exit(1);
	}

	std::cout << "Server is listening on port 8080\n" << std::endl;

	// wait for connection	
	while (!quit) {
		
		sockaddr_in client_addr{};
		socklen_t client_size = sizeof(client_addr);
		int clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_size);
		if (clientfd < 0) {
			perror("Failed to accept connection.");
			continue;
		}

		int flags = fcntl(clientfd, F_GETFL, 0);
		fcntl(clientfd, F_SETFL, flags | O_NONBLOCK);
		
		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
	
		ClientConnection connection {
			clientfd,
			ip,
			ntohs(client_addr.sin_port),
			std::chrono::steady_clock::now()
		};

		std::cout 	<< "[INFO] Connection from " << connection.ip 
					<< " on port " << connection.port << " with file descriptor "
					<< connection.fd << std::endl;
		
		logger.log_event(Logger::LogEvent::CLIENT_CONNECT);

		std::thread t(&Server::handle_client, &server, clientfd);
		t.detach();
	}
	
	// close listening socket
	close(sockfd);
	return 0;
}
