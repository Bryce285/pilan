#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>

std::string parse_cmd(std::string cmd) {
	std::string data;
	
	// implement here

	return data;
}

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
	
	std::this_thread::sleep_for(std::chrono::seconds(5));

	// AUTH STRING MUST BE NULL && NEWLINE TERMINATED
    std::string auth_msg = "AUTH jarlsberg\n\0";
	send(sock, auth_msg.c_str(), auth_msg.size(), 0);

	std::string cmd;

	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');	
	std::cout << "Awaiting command" << std::endl;
	std::getline(std::cin, cmd);

	// TODO
	// parse command
	// assemble protocol-compliant message
	// send message to server
	// handle response
	
	//std::string msg = "LIST\n";
    //send(sock, msg.c_str(), msg.size(), 0);
	
    char buffer[4096];
    int bytes = recv(sock, buffer, sizeof(buffer), 0);
    std::cout << "Server says: " << std::string(buffer, bytes) << "\n";

    close(sock);
}
