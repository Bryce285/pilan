#include "client.hpp"

Client::Client()
{
    crypto_transit.derive_session_key(session_key);
}

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
	    
        crypto_transit.encrypted_string_send(
			data, 
			[&](const uint8_t* data, size_t len) {
				writer.write(data, len); 
			},
			session_key
		);
		
		std::string filepath_str = filepath.string();
		storage_manager.stream_file(filepath_str, writer, session_key);
	}

	// DOWNLOAD command format: DOWNLOAD <filename>
	else if (cmd.rfind("DOWNLOAD", 0) == 0) {
		std::string keyword;
		std::string filename;

		std::istringstream iss(cmd);
		iss >> keyword >> filename;

		data.append(keyword + " " + filename + "\n");

        crypto_transit.encrypted_string_send(
			data, 
			[&](const uint8_t* data, size_t len) {
				writer.write(data, len); 
			}, 
			session_key
		);
	}
	// LIST command format: LIST
	else if (cmd == "LIST") {
		data = "LIST\n";

        crypto_transit.encrypted_string_send(
			data, 
			[&](const uint8_t* data, size_t len) {
				writer.write(data, len); 
			}, 
			session_key
		);
	}
	// DELETE command format: DELETE <filename>
	else if (cmd.rfind("DELETE", 0) == 0) {
		std::string keyword;
		std::string filename;

		std::istringstream iss(cmd);
		iss >> keyword >> filename;

		data.append(keyword + " " + filename + "\n");
		
		std::cout << "Keyword: [" << keyword << "], filename: [" << filename << "]\n";
	
        crypto_transit.encrypted_string_send(
			data, 
			[&](const uint8_t* data, size_t len) {
				writer.write(data, len); 
			}, 
			session_key
		);
	}
	else if (cmd == "QUIT") {
		state.connected = false;
		data = "QUIT\n";

        crypto_transit.encrypted_string_send(
			data, 
			[&](const uint8_t* data, size_t len) {
				writer.write(data, len); 
			}, 
			session_key
		);
	}
	else {
		throw std::runtime_error("Unrecognized command");
	}
}

void Client::parse_msg(ServerState& state, size_t pos)
{
	std::string line(
            reinterpret_cast<const char*>(state.rx_buffer.data()),
            pos
    );

	state.rx_buffer.erase(state.rx_buffer.begin(), state.rx_buffer.begin() + pos + 1);

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
		storage_manager.write_chunk(state.cur_download_handle, state.rx_buffer.data(), to_write);
		state.in_bytes_remaining -= to_write;
		state.rx_buffer.erase(state.rx_buffer.begin(), state.rx_buffer.begin() + to_write);
	}
				
	if (state.in_bytes_remaining == 0) {
		storage_manager.commit_download(state.cur_download_handle);
		state.command = DEFAULT;
		state.connected = false;
		return true;
	}

	return false;
}

bool Client::recv_all(int sock, uint8_t* buf, size_t len) {
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

bool Client::recv_encrypted_msg(int sock, uint8_t session_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], std::vector<uint8_t>& plaintext_out)
{
    uint32_t len_net;
    if (!recv_all(sock, reinterpret_cast<uint8_t*>(&len_net), sizeof(len_net))) {
        return false;
    }

    uint32_t ciphertext_len = ntohl(len_net);

    if (ciphertext_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
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

    crypto_transit.decrypt_message(ciphertext.data(), ciphertext_len, plaintext_out, session_key, nonce);

	return true;
}

void Client::handle_server_msg(ServerState& state, int sock)
{
	//uint8_t buf[4096];

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
        recv_encrypted_msg(sock, session_key, plaintext_buf);
        state.rx_buffer.insert(state.rx_buffer.end(), plaintext_buf.begin(), plaintext_buf.end());
		
		// assemble protocol messages from server
		if (state.command == DEFAULT) {
		    while (true) {
                auto it = std::find(state.rx_buffer.begin(),
                                    state.rx_buffer.end(),
                                    static_cast<uint8_t>('\n'));
                if (it == state.rx_buffer.end())
                    break;

                size_t pos = std::distance(state.rx_buffer.begin(), it);
                parse_msg(state, pos);
            }
        }

		switch (state.command) {
			case DOWNLOAD: {
				if (!download_file(state)) continue;
				break;
			}
			
			case DEFAULT: {
				for (uint8_t c : plaintext_buf) {
					std::cout << c << " ";
				}
				std::cout << std::endl;
			}

			default: {
				break;
			}
		}
	}
}
