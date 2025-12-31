#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>

#include "client.hpp"

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    if (connect(sock, (sockaddr*)&server, sizeof(server)) < 0) {
        std::cerr << "Connection failed\n";
        return 1;
    }
	
	// AUTH STRING MUST BE NULL && NEWLINE TERMINATED
    std::string auth_msg = "AUTH jarlsberg\n\0";
	
	// TODO - send this in a loop just to be safe
	send(sock, auth_msg.c_str(), auth_msg.size(), 0);

	std::string cmd;
	Client::ServerState state;

	while (state.connected) {
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');	
		std::cout << "Awaiting command: " << std::endl;
		std::getline(std::cin, cmd);

		// parse and send command to server
		Client::handle_cmd(state, cmd, sock);

		// handle server response
		Client::handle_server_msg(state, sock);
	}

    close(sock);
}
