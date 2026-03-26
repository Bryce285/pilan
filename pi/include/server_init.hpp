#include <stdexcept>
#include <string>
#include <sys/socket.h>   // socket(), bind(), listen(), accept(), send(), recv()
#include <netinet/in.h>   // sockaddr_in, INADDR_ANY, htons()
#include <arpa/inet.h>    // inet_addr() if needed
#include <unistd.h>       // close()
#include <fcntl.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <variant>

#include "server.hpp"
#include "key_manager.hpp"
#include "logger.hpp"
#include "discovery_server.hpp"

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

		// TODO - move implementation of this function out of the header
  	bool server_init()
    {
      Logger logger;
	    Server server{logger};
	    logger.log_event(Logger::LogEvent::SERVICE_START);
    
        // TODO - make this exit handler work
	    /*
	    std::atexit([&logger]() {
		    logger.log_event(Logger::LogEvent::SERVICE_STOP);
	    });
	    */

	    bool quit = false;

	    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	    if (sockfd < 0) {
		    perror("Failed to create socket.");
		    return false;
	    }

	    sockaddr_in addr{};
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(0);
	    addr.sin_addr.s_addr = INADDR_ANY;

	    int opt = 1;
	    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	    signal(SIGPIPE, SIG_IGN);

	    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		    perror("Failed to bind socket.");
		    return false;
	    }

	    socklen_t len = sizeof(addr);
	    getsockname(sockfd, (struct sockaddr*)&addr, &len);
	    uint16_t actual_port = ntohs(addr.sin_port);
			
			std::thread discovery_thread(DiscoveryServer::init, actual_port);
			discovery_thread.detach();



			// get network info and display it in case client needs to enter info manually
			struct ifaddrs *ifaddr, *ifa;
			if (getifaddrs(&ifaddr) == -1) {
				perror("getifaddrs");
				throw std::runtime_error("Failed to retrieve network information.");
			}
			
			std::cout << "Server Info: " << std::endl;
			std::cout << "Port: " << std::to_string(actual_port) << std::endl;
			std::cout << "Network Interfaces: " << std::endl;

			for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
				if (ifa->ifa_addr == NULL) continue;

				printf("%s\n", ifa->ifa_name);
				if (ifa->ifa_addr->sa_family == AF_INET) {
					char host[INET_ADDRSTRLEN];
					struct sockaddr_in *pAddr = (struct sockaddr_in *)ifa->ifa_addr;
					inet_ntop(AF_INET, &pAddr->sin_addr, host, INET_ADDRSTRLEN);
					printf("\tAddress: %s\n", host);
				}
			}

			freeifaddrs(ifaddr); 


			
	    if (listen(sockfd, 8) < 0) {
		    perror("Listening failed.");
		    return false;
    	}

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

		    logger.log_event(Logger::LogEvent::CLIENT_CONNECT);

		    std::thread t(&Server::handle_client, &server, clientfd);
		    t.detach();
	    }
	
	    close(sockfd);
        return true;
    }
}
