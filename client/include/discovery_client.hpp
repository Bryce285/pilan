#pragma once

#include <netinet/in.h>

namespace DiscoveryClient
{
  struct ServerInfo
  {
    bool discovery_success = false;
    sockaddr_in server_addr{};
    uint16_t port = 0;
  };
  
  void discover(ServerInfo& serv_info_out);
}
