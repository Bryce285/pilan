#include <filesystem>

#pragma once

class PathMgr
{
	private:
		static std::filesystem::path get_home();
		inline static std::string home = get_home();

	public:
		inline static const std::filesystem::path downloads_dir = home + "/Downloads/";
		inline static const std::filesystem::path pilandata_dir = home + "/.pilandata/";
		inline static const std::filesystem::path tmp_dir = home + "/.pilandata/tmp/";
		inline static const std::filesystem::path tak_dir = home + "/.pilandata/tak/";
		inline static const std::filesystem::path tak_path = home + "/.pilandata/tak/pilan.tak";

		static bool mkdirs();
};
