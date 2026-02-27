#include "paths.hpp"

bool PathMgr::mkdirs()
{
	try {
		std::filesystem::create_directories("/data/pilan-client");
		std::filesystem::create_directory("/data/pilan-client/downloads");
		std::filesystem::create_directory("/data/pilan-client/tmp");
		std::filesystem::create_directory("/data/pilan-client/tak");
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
		return false;
	}

	return true;
}
