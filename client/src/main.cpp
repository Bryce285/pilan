#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <chrono>
#include <netdb.h>

#include <sodium.h>

#include "client.hpp"
#include "crypto.hpp"

int main(int argc, char* argv[]) 
{
	bool key_flag_set = false;
	if (argc == 2 && (std::strcmp(argv[1], "-f") == 0)) {
		key_flag_set = true;
	}
	else if (argc > 1) {
		std::cerr << "Usage: " << argv[0] << " [-f]" << std::endl;
		exit(1);
	}
	
	if (sodium_init() < 0) {
		std::cerr << "Failed to initialize libsodium" << std::endl;
		exit(1);
	}
	
	if (key_flag_set) {
		std::string tak;
		std::cout << "Enter your Transfer Authentication Key: ";
		std::getline(std::cin, tak);
		
		try {
			CryptoInTransit::write_tak(tak);
		}
		catch (const std::exception& e) {
			std::cerr << "Failed to write Transfer Authentication Key to file: " << e.what() << std::endl;
			exit(1);
		}
	}

#if LOCALTEST
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

	if (connect(sock, (sockaddr*)&server, sizeof(server)) < 0) {
        std::cerr << "Connection failed\n";
        exit(1);
    }
#else
	struct addrinfo hints{}, *res;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int status = getaddrinfo("pilan.local", "8080", &hints, &res);
	if (status != 0) {
		std::cerr << "getaddrinfo: " << gai_strerror(status) << std::endl;
		exit(1);
	}

	int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock < 0) {
		perror("socket");
		freeaddrinfo(res);
		exit(1);
	}

	if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
		perror("connect");
		freeaddrinfo(res);
		close(sock);
		exit(1);
	}

	freeaddrinfo(res);
#endif

	int flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	
    // authenticate with server
    CryptoInTransit crypto_transit; 

    uint8_t server_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    size_t total = 0;
    while (total < sizeof(server_nonce)) {
        ssize_t n = recv(sock, server_nonce + total, sizeof(server_nonce) - total, 0);
        if (n < 0) {
			if (errno == EINTR) continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) continue;

            throw std::runtime_error("recv failed");
        }
		if (n == 0) {
			throw std::runtime_error("Server closed connection early");
		}

        total += n;
    }
    
	constexpr std::string_view auth_keyword = "AUTH";

	uint8_t auth_tag[crypto_auth_hmacsha256_BYTES];
	crypto_transit.get_auth_tag(auth_tag, server_nonce);
	
	std::vector<uint8_t> auth_msg;
	auth_msg.reserve(auth_keyword.size() + sizeof(auth_tag));

	auth_msg.insert(
    	auth_msg.end(),
    	reinterpret_cast<const uint8_t*>(auth_keyword.data()),
    	reinterpret_cast<const uint8_t*>(auth_keyword.data()) + auth_keyword.size()
	);

	auth_msg.insert(
    	auth_msg.end(),
    	auth_tag,
    	auth_tag + sizeof(auth_tag)
	);

    total = 0;
    while (total < sizeof(auth_tag)) {
        ssize_t sent = send(sock, auth_msg.data() + total, auth_msg.size() - total, 0);
        if (sent <= 0) {
            throw std::runtime_error("Failed to send authentication message");
        }

        total += static_cast<size_t>(sent);
    }

	Client client;
	std::string cmd;
	Client::ServerState state;

	while (state.connected) {
		std::cout << "\033[1;32mpilan\033[0m-> ";
		std::getline(std::cin, cmd);

		try {
			client.handle_cmd(state, cmd, sock);
		}
		catch (const std::exception& e) {
			std::cerr << "Command handling error: " << e.what() << std::endl;
		}

		state.cur_srvr_msg_handled = false;

		client.handle_server_msg(state, sock);
	}

    close(sock);
}
