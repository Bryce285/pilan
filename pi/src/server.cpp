#include "server.hpp"

/*
void Server::set_timeout(int clientfd)
{
	struct timeval tv;
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(clientfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}
*/

bool Server::authenticate(int clientfd)
{
	std::chrono::steady_clock::time_point auth_deadline = 
		std::chrono::steady_clock::now() + std::chrono::seconds(AUTH_TIMEOUT);

    SocketStreamWriter writer(clientfd);

	// client uses nonce to generate authentication tag
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
	storage_manager.crypto_transit.get_nonce(nonce);
	
    size_t total_nonce = 0;
	while (total_nonce < sizeof(nonce)) {
		ssize_t sent = send(clientfd, nonce + total_nonce, sizeof(nonce) - total_nonce, 0);
		if (sent <= 0) {
			std::cerr << "Nonce failed to send" << std::endl;
            return false;
		}

		total_nonce += sent;
	}

	std::cout << "Nonce sent" << std::endl;

	std::vector<uint8_t> rx_buffer;
	uint8_t buf[16384];
    
    // receive auth tag from client
	size_t total_tag = 0;
	while (total_tag < crypto_auth_hmacsha256_BYTES) {
		std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
		if (now > auth_deadline) {
			std::cout << "Authentication timeout" << std::endl;
			return false;
		}

		ssize_t n = recv(clientfd, buf + total_tag, sizeof(buf) - total_tag, 0); 
		if (n < 0) {
			if (errno == EINTR) continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) continue;

			std::cerr << "recv failed" << std::endl;
			return false;
		}
		if (n == 0) {
			std::cerr << "Client closed connection early" << std::endl;
			return false;
		}
		
		total_tag += n;
		rx_buffer.insert(rx_buffer.end(), buf, buf + n);
	}
    
	if (total_tag <= 0) return false;

	constexpr size_t AUTH_LEN = 4;
	constexpr size_t TAG_LEN = crypto_auth_hmacsha256_BYTES;

	if (rx_buffer.size() != AUTH_LEN + TAG_LEN) {
		std::cerr << std::to_string(rx_buffer.size()) << std::endl;
		std::cerr << "Auth message is not of expected length" << std::endl;
		return false;
	}

	if (std::memcmp(rx_buffer.data(), "AUTH", AUTH_LEN) != 0) {
		std::string message = "400 EXPECTED AUTH\n";
		const char* data_ptr = message.c_str();

		size_t total_expect_auth = 0;
		while (total_expect_auth < message.size()) {
			ssize_t sent = send(clientfd, data_ptr + total_expect_auth, message.size() - total_expect_auth, 0);
			if (sent <= 0) {
				std::cerr << "Message failed to send: " << message << std::endl;
			}

			total_expect_auth += sent;
		}

		return false;
	}
   	
	std::cout << "auth tag recv success" << std::endl;

	std::vector<uint8_t> rx_auth_tag;
	rx_auth_tag.insert(
    	rx_auth_tag.end(),
    	rx_buffer.begin() + AUTH_LEN,
    	rx_buffer.end()
	);

	if (!rx_auth_tag.empty() && rx_auth_tag.back() == '\n') {
    	rx_auth_tag.pop_back();
	}

    if (!storage_manager.crypto_transit.verify_auth(rx_auth_tag.data(), nonce, TAK->key_buf)) {
		std::string message = "401 AUTH FAILED\n";
		const char* data_ptr = message.c_str();
		
		size_t total_auth_fail = 0;
		while (total_auth_fail < message.size()) {
			ssize_t sent = send(clientfd, data_ptr + total_auth_fail, message.size() - total_auth_fail, 0);
			if (sent <= 0) {
				std::cerr << "Message failed to send: " << message << std::endl;
			}

			total_auth_fail += sent;
		}

		return false;
	}

	SESSION_KEY = std::make_unique<SecureKey>(KeyType::SESSION, TAK->key_buf);		
	storage_manager.set_session_key(*SESSION_KEY);

	std::cout << "session key derivation success" << std::endl;
   	
	/* 
	std::string message = "200 AUTH OK\n";
    storage_manager.crypto_transit.encrypted_string_send(
		message, 
		[&](const uint8_t* data, size_t len) {
			writer.write(data, len);
		}, 
		SESSION_KEY
	);
	*/

	return true;
}

bool Server::upload_file(ClientState& state)
{
	std::cout << "Entered upload function" << std::endl;

	size_t to_write = std::min(state.in_bytes_remaining, state.rx_buffer.size());

	if (to_write > 0) {
		try {
			storage_manager.write_chunk(*cur_upload_handle, state.rx_buffer.data(), to_write, false);
		}
		catch (const std::exception& e) {
			state.command = DEFAULT;
			
			logger.log_event(Logger::LogEvent::UPLOAD_FAILURE);
			std::cerr << "Failed to write chunk: " << e.what() << std::endl;
			storage_manager.abort_upload(*cur_upload_handle);
		
			return true;
		}

		state.in_bytes_remaining -= to_write;

		sodium_memzero(state.rx_buffer.data(), to_write);
		state.rx_buffer.erase(state.rx_buffer.begin(), state.rx_buffer.begin() + to_write);

		if (state.in_bytes_remaining == 0) {
			storage_manager.write_chunk(*cur_upload_handle, nullptr, 0, true);

			storage_manager.commit_upload(*cur_upload_handle);						
			state.command = DEFAULT;

			logger.log_event(Logger::LogEvent::UPLOAD_COMPLETE);

			return true;
		}
	}

	return false;
}	

void Server::download_file(ClientState& state, int clientfd)
{
    SocketStreamWriter writer(clientfd);

	ServerStorageManager::FileInfo file_info = storage_manager.get_file_info(state.ofilename);
	uint64_t size = file_info.size_bytes;

	// send header
	std::string header = "DOWNLOAD " + state.ofilename + " " + std::to_string(size) + "\n";
    storage_manager.crypto_transit.encrypted_string_send(
		header, 
		[&](const uint8_t* data, size_t len) {
			writer.write(data, len);
		}, 
		SESSION_KEY->key_buf
	);

	try {
		storage_manager.stream_file(state.ofilename, writer);	
	}
	catch (const std::exception& e) {
		logger.log_event(Logger::LogEvent::DOWNLOAD_FAILURE);

		std::cerr << "Failed to stream file: " << e.what() << std::endl;
	}
				
	state.command = DEFAULT;

	logger.log_event(Logger::LogEvent::DOWNLOAD_COMPLETE);
}

void Server::list_files(ClientState& state, int clientfd)
{
    SocketStreamWriter writer(clientfd);
	std::string message;
	
	try{	
		std::vector<ServerStorageManager::FileInfo> files = storage_manager.list_files();
		for (size_t i = 0; i < files.size(); i++) {
			message.append(files[i].name + "\n");
		}
	}
	catch (const std::exception& e) {
		logger.log_event(Logger::LogEvent::FILE_LIST_FAILURE);
		std::cerr << "Failed to get file list: " << e.what() << std::endl;
	}

	std::cout << "Attempting to send files list" << std::endl;
    
    storage_manager.crypto_transit.encrypted_string_send(
		message,  
		[&](const uint8_t* data, size_t len) {
			writer.write(data, len);
		}, 
		SESSION_KEY->key_buf
	);
	
	logger.log_event(Logger::LogEvent::FILE_LIST);

	std::cout << "Files list sent" << std::endl;
	std::cout << message << std::endl;

	state.command = DEFAULT;
}

void Server::delete_file(ClientState& state, int clientfd)
{
    SocketStreamWriter writer(clientfd);

	try {
		storage_manager.delete_file(state.file_to_delete);
	}
	catch (const std::exception& e) {
		logger.log_event(Logger::LogEvent::FILE_DELETE_FAILURE);
		std::cerr << "Failed to delete file: " << e.what() << std::endl;
		state.command = DEFAULT;
		return;
	}

	logger.log_event(Logger::LogEvent::FILE_DELETE);

	std::string message = "File deleted\n";	
    storage_manager.crypto_transit.encrypted_string_send(
		message,  
		[&](const uint8_t* data, size_t len) {
			writer.write(data, len);
		}, 
		SESSION_KEY->key_buf
	);
	
	state.command = DEFAULT;
}

std::string Server::parse_msg(ClientState& state, size_t pos)
{
	std::cout << "Entered message parsing function" << std::endl;

	std::string line(
            reinterpret_cast<const char*>(state.rx_buffer.data()),
            pos
    );
	
	sodium_memzero(state.rx_buffer.data(), pos + 1);
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
		
		std::istringstream iss(line);
		std::string cmd;
		iss >> cmd;

		std::string extra;
		if (iss >> extra) {
			std::cout << "extra input: " << extra << std::endl;
			throw std::runtime_error("Unexpected extra input");
		}
	
		state.command = LIST;
		response = "LISTING\n";
	}
	else if (line.rfind("UPLOAD", 0) == 0) {
					
		/*
		* UPLOAD <filename> <filesize_bytes>\n <binary data>
		* upload a file to the Pi
		*/
		std::cout << "[INFO] Command recieved: UPLOAD" << std::endl;

		std::istringstream iss(line);
		std::string cmd;
		std::string filename;
		size_t bytes_remaining;

		if (!(iss >> cmd >> filename >> bytes_remaining)) {
			throw std::runtime_error("Malformed input. Expected <cmd> <filename> <byte_count>");
		}

		std::string extra;
		if (iss >> extra) {
			throw std::runtime_error("Unexpected extra input");
		}

		if (bytes_remaining == 0) {
			throw std::runtime_error("Byte count cannot be empty");
		}

		state.ifilename = filename;
		state.in_bytes_remaining = bytes_remaining;
		
		try{	
			cur_upload_handle = storage_manager.start_upload(state.ifilename, state.in_bytes_remaining);
		}
		catch (const std::exception& e) {
			std::cerr << "Error starting upload: " << e.what() << std::endl;
		}

		state.command = UPLOAD;
		response = "UPLOADING\n";

		logger.log_event(Logger::LogEvent::UPLOAD_START);
	}
	else if (line.rfind("DOWNLOAD", 0) == 0) {
				
		/*
		* DOWNLOAD <filename>
		* download a file from the Pi
		*/
		std::cout << "[INFO] Command recieved: DOWNLOAD" << std::endl;

		std::istringstream iss(line);
		std::string cmd;
		std::string filename;

		if (!(iss >> cmd >> filename)) {
			throw std::runtime_error("Malformed input. Expected <cmd> <filename>");
		}

		std::string extra;
		if (iss >> extra) {
			throw std::runtime_error("Unexpected extra input");
		}
		
		state.ofilename = filename;
		state.command = DOWNLOAD;

		logger.log_event(Logger::LogEvent::DOWNLOAD_START);
	}
	else if (line.rfind("DELETE", 0) == 0) {

		/*
		* DELETE <filename>
		* delete a file from the Pi
		*/
		std::cout << "[INFO] Command recieved: DELETE" << std::endl;
		
		std::istringstream iss(line);
		std::string cmd;
		std::string filename;

		if (!(iss >> cmd >> filename)) {
			throw std::runtime_error("Malformed input. Expected <cmd> <filename>");
		}
		
		std::string extra;
		if (iss >> extra) {
			throw std::runtime_error("Unexpected extra input");
		}
		
		state.file_to_delete = filename;
		state.command = DELETE;
		response = "DELETING\n";
	}
	else if (line == "QUIT") {	
		std::cout << "[INFO] Command recieved: QUIT" << std::endl;
		
		std::istringstream iss(line);
		std::string cmd;	
		iss >> cmd;

		std::string extra;
		if (iss >> extra) {
			throw std::runtime_error("Unexpected extra input");
		}

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
        if (recvd == 0) {
			std::cerr << "Client closed connection" << std::endl;
            return false;
        }
		if (recvd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			}

			perror("recv");
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

	try {
    	storage_manager.crypto_transit.decrypt_message(ciphertext.data(), ciphertext_len, plaintext_out, session_key, nonce);
	}
	catch (const std::exception& e) {
		std::cerr << "Failed to decrypt message from client: " << e.what() << std::endl;
		return false;
	}

	return true;
}

void Server::client_loop(int clientfd)
{	
    SocketStreamWriter writer(clientfd);
	ClientState state;
	
	std::cout << "entered client loop, " << state.connected << ", " << state.command << std::endl;
	
	while (state.connected) {
        
        std::vector<uint8_t> plaintext_buf;
        bool msg_ok = recv_encrypted_msg(clientfd, SESSION_KEY->key_buf, plaintext_buf);
        state.rx_buffer.insert(state.rx_buffer.end(), plaintext_buf.begin(), plaintext_buf.end());
		
		if (!msg_ok) {
			std::cout << "message not ok" << std::endl;
			state.connected = false;
			break;
		}

		if (state.command == DEFAULT) {
			// assemble protocol messages
			while (true) {
				auto it = std::find(state.rx_buffer.begin(),
                                    state.rx_buffer.end(),
                                    static_cast<uint8_t>('\n'));
                if (it == state.rx_buffer.end())
                    break;

                size_t pos = std::distance(state.rx_buffer.begin(), it);
				std::string response;
				
				try {
					response = parse_msg(state, pos);
				}
				catch (const std::exception& e) {
					std::cerr << "Failed to parse client message: " << e.what() << std::endl;
				}

				// send response
				storage_manager.crypto_transit.encrypted_string_send(
					response, 
					[&](const uint8_t* data, size_t len) {
						writer.write(data, len);
					}, 
					SESSION_KEY->key_buf
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
	//set_timeout(clientfd);
	
	if(!authenticate(clientfd)) {
		logger.log_event(Logger::LogEvent::CLIENT_AUTH_FAILURE);

		close(clientfd);
		return;
	}
	
	logger.log_event(Logger::LogEvent::CLIENT_AUTH_SUCCESS);

	client_loop(clientfd);
	close(clientfd);
}
