#include "server.hpp"

void Server::set_timeout(int clientfd)
{
	struct timeval tv;
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(clientfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

std::string Server::load_auth_key()
{
	// TODO - real implementation of this function

	/* PLACEHOLDER */
	std::string key = "jarlsberg";
	return key;
}

bool Server::authenticate(int clientfd)
{
	std::string rx_buffer;
	bool recieving = true;
	char buf[256];

	size_t total = 0;
	while (recieving) {
		ssize_t n = recv(clientfd, buf, sizeof(buf), 0);
		if (n <= 0) {
			std::cerr << "Failed to recieve AUTH message" << std::endl;
			return false;
		}
		
		total += n;
		rx_buffer.append(buf, n);

		if (rx_buffer.find("\n") != std::string::npos) {
			recieving = false;
		}
	}

	if (total <= 0) return false;

	if (rx_buffer.rfind("AUTH", 0) != 0) {
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

	std::string client_key = rx_buffer.substr(5);
	if (!client_key.empty() && client_key.back() == '\n') {
		client_key.pop_back();
	}

	std::string device_key = load_auth_key();
	size_t len = device_key.length();

	if (CRYPTO_memcmp(client_key.data(), device_key.data(), len)) {
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

	std::string message = "200 AUTH OK\n";
	const char* data_ptr = message.c_str();
	
	total = 0;
	while (total < message.size()) {
		ssize_t sent = send(clientfd, data_ptr + total, message.size() - total, 0);
		if (sent <= 0) {
			std::cerr << "Message failed to send: " << message << std::endl;
		}

		total += sent;
	}
	
	return true;
}

bool Server::upload_file(ClientState& state)
{
	std::cout << "Entered upload function" << std::endl;

	size_t to_write = std::min(state.in_bytes_remaining, state.rx_buffer.size());
	std::string ifilename = state.ifilename + ".tmp";
	std::filesystem::path ifilepath = "/home/bryce/projects/offlinePiFS/pi/pi_storage_test/" + ifilename;

	// check if temp file for ofilename exists, create it if not
	if (!std::filesystem::exists(ifilepath)) {
		std::ofstream tmp(ifilepath);
	}
				
	std::ofstream outFile(ifilepath, std::ios::binary | std::ios::app);
	if (!outFile.is_open()) {
		std::cerr << "Failed to open " << ifilepath.string() << " for upload." << std::endl;
	}

	// if bytes_remaining > 0 write binary data from recv to file
	if (to_write > 0) {
		outFile.write(state.rx_buffer.data(), to_write);
		state.in_bytes_remaining -= to_write;
		state.rx_buffer.erase(0, to_write);
		outFile.close();

		if (state.in_bytes_remaining == 0) {
						
			std::filesystem::path permPath = "/home/bryce/projects/offlinePiFS/pi/pi_storage_test/" + state.ifilename;
			std::filesystem::rename(ifilepath, permPath);
			//TODO - handle rename error
			state.command = DEFAULT;
			return true;
		}

		return false;
	}

	return false;
}	

bool Server::download_file(ClientState& state, int clientfd)
{
	bool done = false;

	std::filesystem::path ofilepath = "/home/bryce/projects/offlinePiFS/pi/pi_storage_test/" + state.ofilename;

	// check if ifilename exists
	if (!std::filesystem::exists(ofilepath)) {
		std::cerr << "File " << ofilepath.string() << " could not be found" << std::endl;
		state.connected = false;
		return done;
	}

	std::ifstream inFile(ofilepath, std::ios::binary);
	if (!inFile.is_open()) {
		std::cerr << "Failed to open " << ofilepath.string() << std::endl;
	}
	
	// get file size and send metadata
	std::uintmax_t size = std::filesystem::file_size(ofilepath);
	std::string metadata = "DOWNLOAD " + state.ofilename + " " + std::to_string(size) + "\n";		
	
	std::cout << "[INFO] Sending command: " << metadata << std::endl;

	size_t total = 0;
	while (total < metadata.size()) {
		ssize_t sent = send(clientfd, metadata.c_str() + total, metadata.size() - total, 0);
		if (sent <= 0) {
			std::cerr << "Failed to send metadata" << std::endl;
		}

		total += sent;
	}

	// send binary data
	char buf[4096];
	while (inFile.read(buf, sizeof(buf)) || inFile.gcount() > 0) {
		ssize_t sent = send(clientfd, buf, inFile.gcount(), 0);
		if (sent <= 0) {
			std::cerr << "Binary data failed to send" << std::endl;	
		}
	}
				
	state.command = DEFAULT;
	done = true;
	return done;
}

void Server::list_files(ClientState& state, int clientfd)
{
	std::cout << "Entered list function" << std::endl;

	std::filesystem::path path = "/home/bryce/projects/offlinePiFS/pi/pi_storage_test"; // TODO - need to change this for deployment on the pi
	std::vector<std::string> filepaths;

	try {
		for (const auto& entry : std::filesystem::directory_iterator(path)) {
			if (std::filesystem::is_regular_file(entry.status())) {
				filepaths.push_back(entry.path().string());
			}
		}
	} 
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
	}

	std::string message;
	for (int i = 0; i < filepaths.size(); i++) {
		message.append(filepaths[i] + "\n");
	}
	
	std::cout << "Attempting to send files list" << std::endl;

	const char* data_ptr = message.c_str();
	size_t total = 0;
	while (total < message.size()) {
		ssize_t sent = send(clientfd, data_ptr + total, message.size() - total, 0);
		if (sent <= 0) {
			std::cerr << "Message failed to send: " << message << std::endl; 
			state.connected = false;
			return;
		}

		total += sent;
	}

	std::cout << "Files list sent" << std::endl;
	std::cout << message << std::endl;

	state.command = DEFAULT;
}

void Server::delete_file(ClientState& state, int clientfd)
{
	// TODO - prevent directory traversal attacks
	std::filesystem::path file = std::filesystem::path("/home/bryce/projects/offlinePiFS/pi/pi_storage_test/") / state.file_to_delete;
	std::string message;
	
	std::cout << "Attempting to delete: " << file << std::endl;
	
	std::cout << "Raw filename: [" << state.file_to_delete << "]\n";

	if (std::filesystem::is_directory(file)) {
    	std::cout << "ERROR: This is a directory, not a file" << std::endl;
	}
	if (!std::filesystem::exists(file)) {
    	std::cout << "ERROR: File does not exist" << std::endl;
	}

	try {
		if (std::filesystem::remove(file)) {
			message = "File deleted: " + file.string();
		}
		else {
			message = "File could not be deleted" + file.string();
		}
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
	}
	
	const char* data_ptr = message.c_str();
	size_t total = 0;
	while (total < message.size()) {
		ssize_t sent = send(clientfd, data_ptr + total, message.size() - total, 0);
		if (sent <= 0) {
			std::cerr << "Message failed to send: " << message << std::endl;
			state.connected = false;
			return;
		}

		total += sent;
	}
	
	state.command = DEFAULT;
}

std::string Server::parse_msg(ClientState& state, size_t pos, int clientfd)
{
	std::string line = state.rx_buffer.substr(0, pos);
	state.rx_buffer.erase(0, pos + 1);

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
		
		//list_files(state, clientfd);

		state.command = LIST;
		response = "LISTING\n";
	}
	else if (line.rfind("UPLOAD", 0) == 0) {
					
		/*
		* UPLOAD <filename> <filesize (bytes)> \n <binary data>
		* upload a file to the Pi
		*/
		std::cout << "[INFO] Command recieved: UPLOAD" << std::endl;

		// TODO - handle errors for unexpected input
		std::istringstream iss(line);
		std::string cmd;
		iss >> cmd >> state.ifilename >> state.in_bytes_remaining;

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

void Server::client_loop(int clientfd)
{
	ClientState state;
	char buf[4096];
	ssize_t n = 0;
	
	std::cout << "entered client loop, " << state.connected << ", " << state.command << std::endl;
	
	while (state.connected) {
			
		// recieve data from the client
		n = recv(clientfd, buf, sizeof(buf), 0);

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
		
		if (state.command == DEFAULT) {
			std::cout << "assembling protocol message" << std::endl;
		
			// assemble protocol messages
			size_t pos;
			while ((pos = state.rx_buffer.find('\n')) != std::string::npos) {

				std::string response = parse_msg(state, pos, clientfd);

				// send response
				ssize_t sent = send(clientfd, response.c_str(), response.size(), 0);
				if (sent < 0) {
					perror("send failed");
					state.connected = false;
					break;
				}	

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
				
				if (!download_file(state, clientfd)) continue;
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
