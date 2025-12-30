#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>

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

void send_binary(std::filesystem::path filepath, int sock)
{
	std::ifstream inFile(filepath, std::ios::binary);
	if (!inFile.is_open()) {
		std::cerr << "Failed to open file: " << filepath << std::endl;
	}

	char buf[4096];
	while (inFile.read(buf, sizeof(buf)) || inFile.gcount() > 0) {
		ssize_t sent = send(sock, buf, inFile.gcount(), 0);
		if (sent <= 0) {
			std::cerr << "Binary data failed to send" << std::endl;
			return;
		}
	}
}

void send_header(std::string header, int sock)
{
	const char* data_ptr = header.c_str();
	size_t total = 0;
	while (total < header.size()) {
		ssize_t sent = send(sock, data_ptr + total, header.size() - total, 0);
		if (sent <= 0) {
			std::cerr << "Message failed to send: " << header << std::endl;
			return;
		}

		total += sent;
	}
}

void handle_cmd(ServerState& state, std::string cmd, int sock) {
	std::string data;
	
	// UPLOAD command format: UPLOAD <filepath>	
	if (cmd.rfind("UPLOAD", 0) == 0) {
		std::string keyword;
		std::filesystem::path filepath;
		std::string filename;
		std::uintmax_t filesize;

		std::istringstream iss(cmd);
		iss >> keyword >> filepath;
	
		filename = filepath.filename().string();	
		filesize = std::filesystem::file_size(filepath);
		std::uintmax_t size_net = htobe64(size);

		data.append(keyword + " " + filename + " " + std::to_string(size_net) + "\n");
		
		send_header(data, sock);
		send_binary(filepath, sock);	
	}
	// DOWNLOAD command format: DOWNLOAD <filename>
	else if (cmd.rfind("DOWNLOAD", 0) == 0) {
		std::string keyword;
		std::string filename;
		
		std::istringstream iss(cmd);
		iss >> keyword >> filename;

		data.append(keyword + " " + filename + "\n");

		send_header(data, sock);
	}
	// LIST command format: LIST
	else if (cmd == "LIST") {
		data = "LIST\n";

		send_header(data, sock);
	}
	// DELETE command format: DELETE <filename>
	else if (cmd.rfind("DELETE", 0) == 0) {
		std::string keyword;
		std::string filename;

		std::istringstream iss(cmd);
		iss >> keyword >> filename;

		data.append(keyword + " " + filename + "\n");

		send_header(data, sock);
	}
	else if (cmd == "QUIT") {
		state.connected = false;
		data = "QUIT\n";

		send_header(data, sock);
	}
	else {
		throw std::runtime_error("Unrecognized command");
	}
}

void parse_msg(ServerState& state, size_t pos)
{
	std::string line = state.rx_buffer.substr(0, pos);
	state.rx_buffer.erase(0, pos + 1);

	if (!line.empty() && line.back() == '\r') {
		line.pop_back();
	}

	// if the server is sending back binary data, recieve it and store it locally
	if (line.rfind("DOWNLOAD", 0) == 0) {
		std::cout << "[INFO] Downloading file" << std::endl;

		state.command = DOWNLOAD;
	}
	else {
		// just display whatever the server has sent
		state.command = DEFAULT;
	}
}

bool download_file(ServerState& state, int sock)
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

void handle_server_msg(ServerState& state, int sock)
{
	char buf[4096];

	while (state.connected) {
		ssize_t n = recv(sock, buf, sizeof(buf), 0);

		if (n == 0) {
			state.connected = false;
			break;
		}

		// treat timeouts as disconnections
		if (n < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				state.connected = false;
				break;
			}

			std::cerr << "recv failed" << std::endl;
			state.connected = false;
			break;
		}

		state.rx_buffer.append(buf, n);

		switch (state.command) {
			case DOWNLOAD: {
				if (!download_file(state, sock)) continue;
				break;
			}

			default: {
				break;
			}
		}

		// assemble protocol messages from server
		size_t pos;
		while ((pos = state.rx_buffer.find('\n')) != std::string::npos) {
			parse_msg(state, pos);	
		}
	}
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
	
	// AUTH STRING MUST BE NULL && NEWLINE TERMINATED
    std::string auth_msg = "AUTH jarlsberg\n\0";
	
	// TODO - send this in a loop just to be safe
	send(sock, auth_msg.c_str(), auth_msg.size(), 0);

	std::string cmd;
	ServerState state;

	while (state.connected) {
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');	
		std::cout << "Awaiting command: " << std::endl;
		std::getline(std::cin, cmd);

		// parse and send command to server
		handle_cmd(state, cmd, sock);

		// handle response
		handle_server_msg(state, sock);
	}

    close(sock);
}
