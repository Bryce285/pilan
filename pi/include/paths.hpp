#include <filesystem>

#pragma once

class PathMgr
{
	public:
				
	    inline static std::filesystem::path log_path;
	
		inline static std::filesystem::path strg_cfg_root;
		inline static std::filesystem::path strg_cfg_files;
		inline static std::filesystem::path strg_cfg_tmp;
		inline static std::filesystem::path strg_cfg_meta;

		inline static std::filesystem::path mdk_path;
        
		bool mkdirs();
    
    private:
        void init_paths();
};
