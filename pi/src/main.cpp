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

#include <sodium.h>

#include "paths.hpp"
#include "server_init.hpp"
#include "local_storage_manager"

// for logging connections
struct ClientConnection 
{
	int fd;
	std::string ip;
	uint16_t port;
	std::chrono::steady_clock::time_point time;	
};

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

    std::string usage = "Usage:\n" 
                + "\t-s\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tstart in server mode\n"
                + "\t-e </path/to/source/file> </path/to/destination/file> \t\tlocal mode encryption\n"
                + "\t-d </path/to/source/file> </path/to/destination/file> \t\tlocal mode decryption\n"
                + "\t-h\t\t\t\t\t\t\t\t\t\t\t\t\t\t\thelp\n"
                + "\t--help\t\t\t\t\t\t\t\t\t\t\t\t\t\t\thelp\n"; 

    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];

        if (arg == "-h"sv || arg == "--help"sv) {
            std::cout << usage;
            exit(0);
        }
        else if (arg == "-s"sv) {
            if (local_encrypt || local_decrypt || server_mode) {
                std::cout << usage;
                exit(0);
            }

            server_mode = true;
            break;
        }
        else if (arg == "-e") {
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
        else if (arg == "-d") {
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
