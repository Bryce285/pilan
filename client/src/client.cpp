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
	SocketStreamWriter writer(sock);

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

		data.append(keyword + " " + filename + " " + std::to_string(filesize) + "\n");
		
		std::cout << "Command sent: " << data << std::endl;
	    
        // TODO - get SESSION_KEY from somewhere
        crypto_transit.encrypted_string_send(data, writer.write, SESSION_KEY);
		
		std::string filepath_str = filepath.string();
		storage_manager.stream_file(filepath_str, writer);
	}

	// DOWNLOAD command format: DOWNLOAD <filename>
	else if (cmd.rfind("DOWNLOAD", 0) == 0) {
		std::string keyword;
		std::string filename;

		std::istringstream iss(cmd);
		iss >> keyword >> filename;

		data.append(keyword + " " + filename + "\n");

        crypto_transit.encrypted_string_send(data, writer.write, SESSION_KEY);
	}
	// LIST command format: LIST
	else if (cmd == "LIST") {
		data = "LIST\n";

        crypto_transit.encrypted_string_send(data, writer.write, SESSION_KEY);
	}
	// DELETE command format: DELETE <filename>
	else if (cmd.rfind("DELETE", 0) == 0) {
		std::string keyword;
		std::string filename;

		std::istringstream iss(cmd);
		iss >> keyword >> filename;

		data.append(keyword + " " + filename + "\n");
		
		std::cout << "Keyword: [" << keyword << "], filename: [" << filename << "]\n";
	
        crypto_transit.encrypted_string_send(data, writer.write, SESSION_KEY);
	}
	else if (cmd == "QUIT") {
		state.connected = false;
		data = "QUIT\n";

        crypto_transit.encrypted_string_send(data, writer.write, SESSION_KEY);
	}
	else {
		throw std::runtime_error("Unrecognized command");
	}
}

void Client::parse_msg(ServerState& state, size_t pos)
{

    // TODO - rewrite this method to work with std::vector instead of string
	std::string line = state.rx_buffer.substr(0, pos);
	state.rx_buffer.erase(0, pos + 1);

	if (!line.empty() && line.back() == '\r') {
		line.pop_back();
	}

	// if the server is sending back binary data, recieve it and store it locally
	if (line.rfind("DOWNLOAD", 0) == 0) {
		std::cout << "[INFO] Command received: " << line << std::endl;
		std::cout << "[INFO] Downloading file" << std::endl;
			
		std::istringstream iss(line);
		std::string cmd;
		iss >> cmd >> state.ifilename >> state.in_bytes_remaining;

		std::cout << "Keyword: [" << cmd << "], filename: [" << state.ifilename << "], filesize: [" << state.in_bytes_remaining << "]\n";
		
		state.cur_download_handle = storage_manager.start_download(state.ifilename, state.in_bytes_remaining);
		state.command = DOWNLOAD;
	}
	else {
		// just display whatever the server has sent
		state.command = DEFAULT;
	}
}

bool Client::download_file(ServerState& state)
{
	size_t to_write = std::min(state.in_bytes_remaining, state.rx_buffer.size());

	if (to_write > 0) {
		// TODO - might need to change the data type of write_chunk data arg to account for max possible size of rx_buffer
		storage_manager.write_chunk(state.cur_download_handle, state.rx_buffer.c_str(), to_write);
		state.in_bytes_remaining -= to_write;
		state.rx_buffer.erase(0, to_write);
	}
				
	if (state.in_bytes_remaining == 0) {
		storage_manager.commit_download(state.cur_download_handle);
		state.command = DEFAULT;
		state.connected = false;
		return true;
	}

	return false;
}

bool Server::recv_all(int sock, uint8_t* buf, size_t len) {
    size_t total = 0;

    while (total < len) {
        ssize_t recvd = recv(sock, buf + total, len - total, 0);
        if (recvd <= 0) {
            return false;
        }
        total += recvd;
    }

    return true;
}

bool Server::recv_encrypted_msg(int sock, const uint8_t session_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], std::vector<uint8_t>& plaintext_out)
{
    uint32_t len_net;
    if (!recv_all(sock, reinterpret_cast<uint8_t*>(&len_net), sizeof(len_net))) {
        return false;
    }

    uint32_t ciphertext_len = ntohl(len_net);

    if (cipher_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return false;
    }

    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    if (!recv_all(sock, nonce, sizeof(nonce))) {
        return false;
    }

    std::vector<uint8_t> ciphertext(ciphertext_len);
    if (!recv_all(sock, ciphertext.data(), ciphertext_len)) {
        return false;
    }

    plaintext_out.resize(ciphertext_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);

    crypto_transit.decrypt_message(ciphertext, plaintext_out, session_key, nonce);
}

void Client::handle_server_msg(ServerState& state, int sock)
{
	char buf[4096];

	while (state.connected) {
        
        /*
		ssize_t n = recv(sock, buf, sizeof(buf), 0);

		if (n == 0) {
			state.connected = false;
			break;
		}

		if (n < 0) {
			if (errno != EWOULDBLOCK && errno != EAGAIN) {
				std::cerr << "recv failed" << std::endl;
				state.connected = false;
				break;
			}
			
			continue;
		}

		if (n > 0) state.rx_buffer.append(buf, n);
        */

        std::vector<uint8_t> plaintext_buf;
        recv_encrypted_msg(clientfd, SESSION_KEY, plaintext_buf);
        state.rx_buffer.insert(state.rx_buffer.end(), plaintext_buf.begin(), plaintext_buf.end());
		
		// assemble protocol messages from server
		if (state.command == DEFAULT) {
			size_t pos;
			while ((pos = state.rx_buffer.find('\n')) != std::string::npos) {
				parse_msg(state, pos);
			}
		}

		switch (state.command) {
			case DOWNLOAD: {
				if (!download_file(state)) continue;
				break;
			}
			
			case DEFAULT: {
				std::cout << buf << std::endl;
			}

			default: {
				break;
			}
		}
	}
}
