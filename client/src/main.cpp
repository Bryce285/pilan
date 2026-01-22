#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <chrono>

#include <sodium.h>

#include "client.hpp"
#include "crypto.hpp"

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

	int flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	
    // authenticate with server
    CryptoInTransit crypto_transit; 

    uint8_t server_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    size_t total = 0;
    while (total < sizeof(server_nonce)) {
        ssize_t n = recv(sock, server_nonce, sizeof(server_nonce), 0);
        if (n <= 0) {
            throw std::runtime_error("Failed to receive nonce from server");
        }

        total += n;
    }
    
    uint8_t auth_tag[crypto_auth_hmacsha256_BYTES];
    crypto_transit.get_auth_tag(auth_tag, server_nonce);
    uint8_t auth_keyword[] = reinterpret_cast<uint8_t>("AUTH");

    uint8_t auth_msg[std::size(auth_tag) + std::size(auth_keyword)];
    std::copy(auth_keyword, auth_keyword + std::size(auth_keyword), auth_msg);
    std::copy(auth_tag, auth_tag + std::size(auth_tag), auth_msg);

    total = 0;
    while (total < sizeof(auth_tag)) {
        ssize_t sent = send(sock, auth_msg + total, std::size(auth_msg) - total, 0);
        if (sent <= 0) {
            throw std::runtime_error("Failed to send authentication message");
        }

        total += sent;
    }



	Client client;
	std::string cmd;
	Client::ServerState state;

	while (state.connected) {
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');	
		std::cout << "Awaiting command: " << std::endl;
		std::getline(std::cin, cmd);

		// parse and send command to server
		client.handle_cmd(state, cmd, sock);

		// handle server response
		client.handle_server_msg(state, sock);
	}

    close(sock);
}
