#include <chrono>
#include <fstream>
#include <string>
#include <optional>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <cstdlib>

#pragma once

namespace Utils
{
    inline uint64_t unix_timestamp_ms()
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
    
    std::optional<std::string> parse_config();
}   
