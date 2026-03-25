#include <sys/socket.h>   // socket(), bind(), listen(), accept(), send(), recv()
#include <netinet/in.h>   // sockaddr_in, INADDR_ANY, htons()
#include <arpa/inet.h>    // inet_addr() if needed
#include <unistd.h>       // close()
#include <fcntl.h>

#include <thread>

#include "server.hpp"
#include "key_manager.hpp"
#include "logger.hpp"

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
			// TODO - now that we have the actual port we can start the
			// discovery server on a separate thread
			//
			// We should also display the ip/port info in case automatic discovery
			// fails and the user needs to enter the information manually

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
