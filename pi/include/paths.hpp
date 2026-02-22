#include <filesystem>

#pragma once

/*
	These paths are for testing on a dev machine. Put whatever you want here
*/
namespace DevPaths
{
	inline const std::filesystem::path log_path = "/home/bryce/projects/offlinePiFS/pi/data/logs/pilan.log";

	inline const std::filesystem::path strg_cfg_root = "/home/bryce/projects/offlinePiFS/pi/data/";
	inline const std::filesystem::path strg_cfg_files = "/home/bryce/projects/offlinePiFS/pi/data/files/";
	inline const std::filesystem::path strg_cfg_tmp = "/home/bryce/projects/offlinePiFS/pi/data/tmp/";
	inline const std::filesystem::path strg_cfg_meta = "/home/bryce/projects/offlinePiFS/pi/data/meta/";

	inline const std::filesystem::path mdk_path = "/home/bryce/projects/offlinePiFS/pi/mdk_tmp_path/pilan.mdk";	
	inline const std::filesystem::path tak_path = "/home/bryce/projects/offlinePiFS/pi/tak_tmp_path/pilan.tak";
}

/*
	These paths are for the pi filesystem
*/
namespace ProdPaths
{
	inline const std::filesystem::path log_path = "/data/logs/pilan.log";
	
	inline const std::filesystem::path strg_cfg_root = "/data/";
	inline const std::filesystem::path strg_cfg_files = "/data/files/";
	inline const std::filesystem::path strg_cfg_tmp = "/data/tmp/";
	inline const std::filesystem::path strg_cfg_meta = "/data/meta/";

	inline const std::filesystem::path mdk_path = "/data/mdk/pilan.mdk";
	inline const std::filesystem::path tak_path = "/data/tak/pilan.tak";
}
