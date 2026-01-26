#include "server.hpp"

Server::Server()
{
	key_manager.load_or_gen_mdk(MDK);
	key_manager.derive_key(MDK, FEK, fek_context, fek_subkey_id);
	key_manager.derive_key(MDK, TAK, tak_context, tak_subkey_id);
}

void Server::set_timeout(int clientfd)
{
	struct timeval tv;
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(clientfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

bool Server::authenticate(int clientfd)
{
    SocketStreamWriter writer(clientfd);

	// client uses nonce to generate authentication tag
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
	storage_manager.crypto_transit.get_nonce(nonce);
	
    size_t total = 0;
	while (total < sizeof(nonce)) {
		ssize_t sent = send(clientfd, nonce + total, sizeof(nonce) - total, 0);
		if (sent <= 0) {
			std::cerr << "Nonce failed to send" << std::endl;
            return false;
		}

		total += sent;
	}

	std::vector<uint8_t> rx_buffer;
	uint8_t buf[16384];
    
    // receive auth tag from client
	total = 0;
	while (total < crypto_auth_hmacsha256_BYTES) {
		ssize_t n = recv(clientfd, buf, sizeof(buf), 0);
		if (n <= 0) {
			std::cerr << "Failed to recieve AUTH message" << std::endl;
			return false;
		}
		
		total += n;
		rx_buffer.insert(rx_buffer.end(), std::begin(buf), std::end(buf));
	}
    
	if (total <= 0) return false;

	if (rx_buffer.size() < 4 || std::memcmp(rx_buffer.data(), "AUTH", 4) != 0) {
		std::string message = "400 EXPECTED AUTH\n";
		const char* data_ptr = message.c_str();

		total = 0;
		while (total < message.size()) {
			ssize_t sent = send(clientfd, data_ptr + total, message.size() - total, 0);
			if (sent <= 0) {
				std::cerr << "Message failed to send: " << message << std::endl;
			}

			total += sent;
		}

		return false;
	}
    
    const size_t OFFSET = 5; // index past the protocol command
    std::vector<uint8_t> rx_auth_tag;
    std::copy_n(rx_buffer.begin() + OFFSET, rx_buffer.size(), rx_auth_tag.begin()); 

	if (!rx_auth_tag.empty() && rx_auth_tag.back() == '\n') {
		rx_auth_tag.pop_back();
	}
    
    if (!storage_manager.crypto_transit.verify_auth(rx_auth_tag.data(), nonce, TAK)) {
		std::string message = "401 AUTH FAILED\n";
		const char* data_ptr = message.c_str();
		
		size_t total = 0;
		while (total < message.size()) {
			ssize_t sent = send(clientfd, data_ptr + total, message.size() - total, 0);
			if (sent <= 0) {
				std::cerr << "Message failed to send: " << message << std::endl;
			}

			total += sent;
		}

		return false;
	}

    storage_manager.crypto_transit.derive_session_key(SESSION_KEY, TAK);
    
	std::string message = "200 AUTH OK\n";
    storage_manager.crypto_transit.encrypted_string_send(
		message, 
		[&](const uint8_t* data, size_t len) {
			writer.write(data, len);
		}, 
		SESSION_KEY
	);

	return true;
}

bool Server::upload_file(ClientState& state)
{
	std::cout << "Entered upload function" << std::endl;

	size_t to_write = std::min(state.in_bytes_remaining, state.rx_buffer.size());

	if (to_write > 0) {

        if (state.in_bytes_remaining - to_write == 0) {
		    storage_manager.write_chunk(cur_upload_handle, state.rx_buffer.data(), to_write, true);
        }
        else {
		    storage_manager.write_chunk(cur_upload_handle, state.rx_buffer.data(), to_write, false);
        }

		state.in_bytes_remaining -= to_write;
		state.rx_buffer.erase(state.rx_buffer.begin(), state.rx_buffer.begin() + to_write);

		if (state.in_bytes_remaining == 0) {
			storage_manager.commit_upload(cur_upload_handle);						
			state.command = DEFAULT;
			return true;
		}
	}

	return false;
}	

void Server::download_file(ClientState& state, int clientfd)
{
    SocketStreamWriter writer(clientfd);

	std::filesystem::path path = config.files_dir / state.ofilename;
	uint64_t size = std::filesystem::file_size(path);

	// send header
	std::string header = "DOWNLOAD " + state.ofilename + " " + std::to_string(size) + "\n";
    storage_manager.crypto_transit.encrypted_string_send(
		header, 
		[&](const uint8_t* data, size_t len) {
			writer.write(data, len);
		}, 
		SESSION_KEY
	);

	try {
		storage_manager.stream_file(state.ofilename, writer);	
	}
	catch (const std::exception& e) {
		std::cerr << "Failed to stream file: " << e.what() << std::endl;
	}
				
	state.command = DEFAULT;
}

void Server::list_files(ClientState& state, int clientfd)
{
    SocketStreamWriter writer(clientfd);
	
	std::cout << "Entered list function" << std::endl;
	
	std::vector<ServerStorageManager::FileInfo> files = storage_manager.list_files();

	std::string message;
	for (int i = 0; i < files.size(); i++) {
		message.append(files[i].name + "\n");
	}
	
	std::cout << "Attempting to send files list" << std::endl;
    
    storage_manager.crypto_transit.encrypted_string_send(
		message,  
		[&](const uint8_t* data, size_t len) {
			writer.write(data, len);
		}, 
		SESSION_KEY
	);

	std::cout << "Files list sent" << std::endl;
	std::cout << message << std::endl;

	state.command = DEFAULT;
}

void Server::delete_file(ClientState& state, int clientfd)
{
    SocketStreamWriter writer(clientfd);

	storage_manager.delete_file(state.file_to_delete);

	std::string message = "File deleted\n";	
    storage_manager.crypto_transit.encrypted_string_send(
		message,  
		[&](const uint8_t* data, size_t len) {
			writer.write(data, len);
		}, 
		SESSION_KEY
	);

	state.command = DEFAULT;
}

std::string Server::parse_msg(ClientState& state, size_t pos, int clientfd)
{
	std::string line(
            reinterpret_cast<const char*>(state.rx_buffer.data()),
            pos
    );

	state.rx_buffer.erase(state.rx_buffer.begin(), state.rx_buffer.begin() + pos + 1);

	if (!line.empty() && line.back() == '\r') {
		line.pop_back();
	}		
	
	// parse commands
	std::string response;

	if (line == "LIST") {

		/* 
	 	* LIST
	 	* lists all files that are stored on the Pi
 		*/
		std::cout << "[INFO] Command recieved: LIST" << std::endl;
		
		state.command = LIST;
		response = "LISTING\n";
	}
	else if (line.rfind("UPLOAD", 0) == 0) {
					
		/*
		* UPLOAD <filename> <filesize_bytes>\n <binary data>
		* upload a file to the Pi
		*/
		std::cout << "[INFO] Command recieved: UPLOAD" << std::endl;

		// TODO - handle errors for unexpected input
		std::istringstream iss(line);
		std::string cmd;
		iss >> cmd >> state.ifilename >> state.in_bytes_remaining;
		
		cur_upload_handle = storage_manager.start_upload(state.ifilename, state.in_bytes_remaining);

		state.command = UPLOAD;
		response = "UPLOADING\n";
	}
	else if (line.rfind("DOWNLOAD", 0) == 0) {
				
		/*
		* DOWNLOAD <filename>
		* download a file from the Pi
		*/
		std::cout << "[INFO] Command recieved: DOWNLOAD" << std::endl;

		// TODO - handle errors for unexpected input
		std::istringstream iss(line);
		std::string cmd;
		iss >> cmd >> state.ofilename;	

		state.command = DOWNLOAD;
	}
	else if (line.rfind("DELETE", 0) == 0) {

		/*
		* DELETE <filename>
		* delete a file from the Pi
		*/
		std::cout << "[INFO] Command recieved: DELETE" << std::endl;
		
		std::istringstream iss(line);
		std::string cmd;
		iss >> cmd >> state.file_to_delete;

		state.command = DELETE;
		response = "DELETING\n";
	}
	else if (line == "QUIT") {	
		std::cout << "[INFO] Command recieved: QUIT" << std::endl;

		response = "200 BYE\n";
	}
	else {
		std::cout << "[INFO] Command recieved: UNKNOWN" << std::endl;

		response = "400 UNKNOWN COMMAND\n";
	}

	return response;	
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

    storage_manager.crypto_transit.decrypt_message(ciphertext.data(), ciphertext_len, plaintext_out, session_key, nonce);
	
	return true;
}

void Server::client_loop(int clientfd)
{	
    SocketStreamWriter writer(clientfd);

	ClientState state;
	uint8_t buf[16384];
	ssize_t n = 0;
	
	std::cout << "entered client loop, " << state.connected << ", " << state.command << std::endl;
	
	while (state.connected) {
			
		// recieve data from the client
		/*n = recv(clientfd, buf, sizeof(buf), 0);

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

		if (n > 0) state.rx_buffer.append(buf, n);*/
        
        std::vector<uint8_t> plaintext_buf;
        recv_encrypted_msg(clientfd, SESSION_KEY, plaintext_buf);
        state.rx_buffer.insert(state.rx_buffer.end(), plaintext_buf.begin(), plaintext_buf.end());
		
		if (state.command == DEFAULT) {
			std::cout << "assembling protocol message" << std::endl;
		
            // TODO - possible bug: if we are in default mode and receive a chunk that
            // contains a partial protocol header (not \n terminated), i think we will
            // exit out of the client loop instead of looping back to receive another
            // chunk

			// assemble protocol messages
			while (true) {
                auto it = std::find(state.rx_buffer.begin(),
                                    state.rx_buffer.end(),
                                    static_cast<uint8_t>('\n'));
                if (it == state.rx_buffer.end())
                    break;

                size_t pos = std::distance(state.rx_buffer.begin(), it);
				std::string response = parse_msg(state, pos, clientfd);

				// send response
                // TODO - encrypted_string_send return value should be a bool so we can easily error check
                storage_manager.crypto_transit.encrypted_string_send(
					response, 
					[&](const uint8_t* data, size_t len) {
						writer.write(data, len);
					}, 
					SESSION_KEY
				);

				if (response == "200 BYE\n") {
					state.connected = false;
					break;
				}
			}
		}

		switch (state.command) {
			case LIST: {
				
				list_files(state, clientfd);	
				break;
			}

			case UPLOAD: {
				
				if (!upload_file(state)) continue;
				break;
			}

			case DOWNLOAD: {
				
				download_file(state, clientfd);
				break;
			}

			case DELETE: {
				
				delete_file(state, clientfd);
				break;
			}

			default: {
				break;
			}
		}
	}

	if (state.file_fd >= 0)
		close(state.file_fd);

	std::cout << "Leaving client loop" << std::endl;
}

void Server::handle_client(int clientfd)
{
	set_timeout(clientfd);
	
	if(!authenticate(clientfd)) {
		close(clientfd);
		return;
	}
	
	client_loop(clientfd);
	close(clientfd);
}
