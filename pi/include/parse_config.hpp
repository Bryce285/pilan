#include <optional>
#include <string>

#pragma once

class ConfigParser
{
  public:
    std::optional<std::string> parse_config();
};
