#include "paths.hpp"

#include <pwd.h>
#include <stdexcept>
#include <unistd.h>
#include <filesystem>
#include <iostream>

std::filesystem::path PathMgr::get_home()
{
	struct passwd* pw = getpwuid(getuid());
	if (pw) {
		std::filesystem::path home_path = pw->pw_dir;
		return home_path.lexically_normal();
	}

	return "";
}

bool PathMgr::mkdirs()
{
	if (home.empty()) {
		std::cerr << "Failed to get home directory." << std::endl;
		return false;
	}
	
	try {
		std::filesystem::create_directory(downloads_dir);
		std::filesystem::create_directory(tmp_dir);
		std::filesystem::create_directory(tak_dir);
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
		return false;
	}

	return true;
}
