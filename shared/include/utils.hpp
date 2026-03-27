#include <algorithm>
#include <chrono>
#include <termios.h>
#include <unistd.h>
#include <cctype>
#include <iostream>
#include <cstdlib>
#include <optional>

#pragma once

namespace Utils
{
  class TerminalEchoGuard
  {
    termios oldt;

    public:
      TerminalEchoGuard() {
        tcgetattr(STDIN_FILENO, &oldt);
        termios newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
      }

      ~TerminalEchoGuard() {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
      }  
  };

  inline uint64_t unix_timestamp_ms() {
    using namespace std::chrono;
    return std::chrono::duration_cast<milliseconds>(
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
            [](unsigned char ch) { return !std::isspace(ch); }
      ).base(),
      s.end()  
    );
  }

  static inline void trim(std::string& s) {
    ltrim(s);
    rtrim(s);
  }
}
