#include "client.hpp"

void Client::send_binary(std::filesystem::path filepath, int sock)
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

void Client::send_header(std::string header, int sock)
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

void Client::handle_cmd(ServerState& state, std::string cmd, int sock) {
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
		std::uintmax_t size_net = htobe64(filesize);

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
		
		std::cout << "Keyword: [" << keyword << "], filename: [" << filename << "]\n";

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

void Client::parse_msg(ServerState& state, size_t pos)
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

void Client::handle_server_msg(ServerState& state, int sock)
{
	char buf[4096];

	while (state.connected) {

		// TODO - need to recieve the data in its own loop so it doesn't block the rest of the loop
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
				if (!download_file(state, buf, n, sock)) continue;
				break;
			}
			
			case DEFAULT: {
				std::cout << buf << std::endl;
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
