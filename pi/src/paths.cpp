#include "paths.hpp"

bool PathMgr::mkdirs()
{
	try {
		std::filesystem::create_directory("/data");
		std::filesystem::create_directory("/data/logs");
		std::filesystem::create_directory("/data/files");
		std::filesystem::create_directory("/data/tmp");
		std::filesystem::create_directory("/data/meta");
		std::filesystem::create_directory("/data/mdk");
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
		return false;
	}

	return true;
}
