#include <vector>
#include <string>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <filesystem>
#include <csignal>
#include <cstring>
#include <iomanip>

#include <sodium.h>

#include "paths.hpp"
#include "server_init.hpp"
#include "local_storage_manager.hpp"
#include "logger.hpp"
#include "server_storage_manager.hpp"

int main(int argc, char* argv[])
{
    bool server_mode = false;
    bool local_encrypt = false;
    bool local_decrypt = false;
    std::filesystem::path src;
    std::filesystem::path dest;
    bool create_meta = false;

    struct Option {
    	std::string flag;
    	std::string description;
    };

    std::vector<Option> options = {
        {"-s, --server", "start in server mode"},
        {"-e <src> <dst>, --encrypt <src> <dst>", "local mode encryption"},
        {"-d <src> <dst>, --decrypt <src> <dst>", "local mode decryption"},
        {"-m, --meta", "create metadata for local file encryptions"},
        {"-h, --help", "show help"}
	  };

    std::ostringstream oss;
    oss << "Usage:\n\n";
    oss << "Welcome to pilan.\nRead the docs: <link_here>\nFor more configuration options, edit ~/.pilanconfig\n\n"; 

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
        else if (arg == std::string_view("-s") || arg == std::string_view("--server")) {
            if (local_encrypt || local_decrypt || server_mode) {
                std::cout << usage;
                exit(0);
            }

            server_mode = true;
            break;
        }
        else if (arg == std::string_view("-e") || arg == std::string_view("--encrypt")) {
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
        else if (arg == std::string_view("-d") || arg == std::string_view("--decrypt")) {
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
        else if (arg == std::string_view("-m") || arg == std::string_view("--meta")) {
            if (server_mode) {
                std::cout << usage;
                exit(0);
            }
            create_meta = true;
        }
    }

    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        exit(1);
    }

    PathMgr path_mgr;
    if (!path_mgr.mkdirs()) {
        std::cerr << "Failed to create directories" << std::endl;
		    exit(1);
	}

	KeyManager::init(path_mgr);

    if (server_mode) {
		    Logger::init(path_mgr);
	      ServerStorageManager::init(path_mgr);
	      if (!ServerInit::server_init()){
            exit(1);
        }
    }
    else if (local_encrypt) {
		    LocalStorageManager::init(path_mgr);
        LocalStorageManager mgr{LocalStorageManager::Mode::ENCRYPT, src, dest, create_meta};
    }
    else if (local_decrypt) {
		    LocalStorageManager::init(path_mgr);
        LocalStorageManager mgr{LocalStorageManager::Mode::DECRYPT, src, dest, create_meta};
    }
    else {
        std::cerr << "Mode error: valid state not detected" << std::endl;
        exit(1);
    }

	exit(0);
}
