#include <optional>
#include <string>

#pragma once

class ConfigParser
{
  public:
    static std::optional<std::string> parse_config();
};
