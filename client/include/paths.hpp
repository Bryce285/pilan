#include <filesystem>
#include <iostream>

#pragma once

class PathMgr
{
	public:
		inline static const std::filesystem::path downloads_dir = "/data/pilan-client/downloads/";
		inline static const std::filesystem::path tmp_dir = "/data/pilan-client/tmp/";
		inline static const std::filesystem::path tak_path = "/data/pilan-client/tak/pilan.tak";

		static bool mkdirs();
};
