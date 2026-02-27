#include <filesystem>
#include <iostream>

#pragma once

class PathMgr
{
	public:
				
		inline static const std::filesystem::path log_path = "/data/logs/pilan.log";
	
		inline static const std::filesystem::path strg_cfg_root = "/data/";
		inline static const std::filesystem::path strg_cfg_files = "/data/files/";
		inline static const std::filesystem::path strg_cfg_tmp = "/data/tmp/";
		inline static const std::filesystem::path strg_cfg_meta = "/data/meta/";

		inline static const std::filesystem::path mdk_path = "/data/mdk/pilan.mdk";

		static bool mkdirs();
};
