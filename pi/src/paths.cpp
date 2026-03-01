#include "paths.hpp"

void PathMgr::init_paths()
{
    auto root_dir = Utils.parse_config();

    if (root_dir) {
        strg_cfg_root = root_dir;
    }
    else {
        strg_cfg_root = "/data/";
    }

    log_path = strg_cfg_root / "logs/pilan.log";
    strg_cfg_files = strg_cfg_root / "files/";
    strg_cfg_tmp = strg_cfg_root / "tmp/";
    strg_cfg_meta = strg_cfg_root / "meta/";
    mdk_path = strg_cfg_root / "mdk/pilan.mdk";
}

bool PathMgr::mkdirs()
{
	try {
		std::filesystem::create_directory(strg_cfg_root);
		std::filesystem::create_directory(log_path.parent_path());
		std::filesystem::create_directory(strg_cfg_files);
		std::filesystem::create_directory(strg_cfg_tmp);
		std::filesystem::create_directory(strg_cfg_meta);
		std::filesystem::create_directory(mdk_path.parent_path());
	}
	catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Filesystem error: " << e.what() << std::endl;
		return false;
	}

	return true;
}
