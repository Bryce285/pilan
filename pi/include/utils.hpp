#include <chrono>
#include <fstream>
#include <string>
#include <optional>
#include <algorithm>
#include <cctype>

#pragma once

namespace Utils
{
    uint64_t ServerStorageManager::unix_timestamp_ms()
    {
	    using namespace std::chrono;
        return duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        ).count();
    }

    static inline void ltrim(std::string& s) {
        s.erase(s.begin(),
            std::find_if(s.begin(), s.end(),
                [](unsigned char ch) { return !std::isspace(ch); }));
    }

    static inline void rtrim(std::string& s) {
        s.erase(
            std::find_if(s.rbegin(), s.rend(),
                [](unsigned char ch) { return !std::isspace(ch); }).base(),
            s.end());
    }

    static inline void trim(std::string& s) {
        ltrim(s);
        rtrim(s);
    }
    
    /* This is a simple parsing function to parse a config file with the single
     * line: pilan_root=/path/to/directory 
     * This function should be expanded later to accomodate a more complex config file
     */
    std::optional<std::string> parse_config()
    {
        std::ifstream file("~/.pilan-config");
        if (!file.is_open()) {
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
