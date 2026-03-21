#include "utils.hpp"

// TODO - clean this up, maybe move parsing out of utils namespace
namespace Utils
{
	/* This is a simple parsing function to parse a config file with the single
     * line: pilan_root=/path/to/directory 
     * This function should be expanded later to accomodate a more complex config file
     */
    std::optional<std::string> parse_config()
    {
		std::string home = std::getenv("HOME");
		std::string path = home + "/.pilanconfig";
        std::ifstream file(path);
        if (!file.is_open()) {
			std::cout << "Config file not detected. Using defaults." << std::endl;
            return std::nullopt;
        }

        std::string line;
        const std::string key = "pilan_root";

        while (std::getline(file, line)) {
            trim(line);

            if (line.empty() || line[0] == '#') {
                continue;
            }

            auto eq_pos = line.find('=');
            if (eq_pos == std::string::npos) {
                continue;
            }

            std::string lhs = line.substr(0, eq_pos);
            std::string rhs = line.substr(eq_pos + 1);

            trim(lhs);
            trim(rhs);

            if (lhs == key && !rhs.empty()) {
                return rhs;
            }
        }

        return std::nullopt;
    }
}
