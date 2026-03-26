#include "discovery_client.hpp"

#include <asm-generic/socket.h>
#include <limits>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdexcept>

namespace DiscoveryClient
{
  void discover(ServerInfo& serv_info_out)
  {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    addr.sin_addr.s_addr = inet_addr("255.255.255.255");

    sendto(sock, "DISCOVER_SERVER", 15, 0,
          (struct sockaddr*)&addr, sizeof(addr));

    char buffer[1024];
    sockaddr_in serv_addr;
    socklen_t len = sizeof(serv_addr);

    ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0,
                        (struct sockaddr*)&serv_addr, &len);

    if (n > 0 && std::string(buffer, n).starts_with("PORT:")) {
      std::string data = std::string(buffer, n);
      data.erase(0, 5);      

      int value = std::stoi(data);

      if (value < std::numeric_limits<uint16_t>::min() || value > std::numeric_limits<uint16_t>::max()) {
        throw std::runtime_error("Invalid port received from server: " + std::to_string(value));
      }

      serv_info_out.server_addr = addr;
      serv_info_out.port = value;
      serv_info_out.discovery_success = true;
    }
  }
}
