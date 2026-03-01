#include <filesystem>
#include <iostream>

#pragma once

class PathMgr
{
	public:
				
	    std::filesystem::path log_path;
	
		std::filesystem::path strg_cfg_root;
		std::filesystem::path strg_cfg_files;
		std::filesystem::path strg_cfg_tmp;
		std::filesystem::path strg_cfg_meta;

		std::filesystem::path mdk_path;
        
		bool mkdirs();
    
    private:
        void init_paths();
};
