#include <vector>
#include <chrono>
#include <string>
#include <iostream>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <csignal>
#include <cstring>
#include <iomanip>

#include <sodium.h>

#include "paths.hpp"
#include "server_init.hpp"
#include "local_storage_manager.hpp"

/*
 *  Usage
 *
 *  -s                                                          start in server mode
 *  -e </path/to/source/file> </path/to/destination/file>       local mode encryption
 *  -d </path/to/source/file> </path/to/destination/file>       local mode decryption
 *  -h                                                          help
 *  --help                                                      help
 */

int main(int argc, char* argv[])
{
    bool server_mode = false;
    bool local_encrypt = false;
    bool local_decrypt = false;
    std::filesystem::path src;
    std::filesystem::path dest;

	struct Option {
    	std::string flag;
    	std::string description;
	};

	std::vector<Option> options = {
    	{"-s", "start in server mode"},
    	{"-e <src> <dst>", "local mode encryption"},
    	{"-d <src> <dst>", "local mode decryption"},
    	{"-h, --help", "show help"}
	};

	std::ostringstream oss;
	oss << "Usage:\n\n";

	for (const auto& opt : options) {
    	oss << "  " << std::left << std::setw(30)
        	<< opt.flag
        	<< opt.description << "\n";
	}

	std::string usage = oss.str();

    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];

        if (arg == std::string_view("-h") || arg == std::string_view("--help")) {
            std::cout << usage;
            exit(0);
        }
        else if (arg == std::string_view("-s")) {
            if (local_encrypt || local_decrypt || server_mode) {
                std::cout << usage;
                exit(0);
            }

            server_mode = true;
            break;
        }
        else if (arg == std::string_view("-e")) {
            if (server_mode || local_encrypt || local_decrypt) {
                std::cout << usage;
                exit(0);
            }
            if (!(argv[i + 1] && argv[i + 2])) {
                std::cout << usage;
                exit(0);
            }
            src = argv[i + 1];
            dest = argv[i + 2];  

            local_encrypt = true;
        }
        else if (arg == std::string_view("-d")) {
            if (server_mode || local_encrypt || local_decrypt) {
                std::cout << usage;
                exit(0);
            }
            if (!(argv[i + 1] && argv[i + 2])) {
                std::cout << usage;
                exit(0);
            }
            src = argv[i + 1];
            dest = argv[i + 2]; 
             
            local_decrypt = true;
        }
    }

    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        exit(1);
    }
    
    if (!PathMgr::mkdirs()) {
		exit(1);
	}
    	
    if (server_mode) {
	    if (!ServerInit::server_init()){
            exit(1);
        }
    }
    else if (local_encrypt) {
        LocalStorageManager mgr{LocalStorageManager::ENCRYPT, src, dest};
    }
    else if (local_decrypt) {
        LocalStorageManager mgr{LocalStorageManager::DECRYPT, src, dest};
    }
    else {
        std::cerr << "Mode error: valid state not detected" << std::endl;
        exit(1);
    }

	exit(0);
}
