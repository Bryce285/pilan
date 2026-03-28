#include "discovery_server.hpp"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <string>
#include <cstdint>
#include <unistd.h>

namespace DiscoveryServer
{
  void init(uint16_t actual_port)
  {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
      perror("socket failed");
      throw std::runtime_error("socket failed");
    }

    sockaddr_in udp_addr{};
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_port = htons(9999);
    udp_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udp_sock, (struct sockaddr*)&udp_addr, sizeof(udp_addr)) != 0) {
      perror("bind failed");
      close(udp_sock);
      throw std::runtime_error("Could not bind to discovery port.");
    }

    std::cout << "Discovery server listening on UDP port 9999...\n";

    while (true) {
      char buffer[1024];
      sockaddr_in client_addr{};
      socklen_t len = sizeof(client_addr);

      ssize_t n = recvfrom(udp_sock, buffer, sizeof(buffer), 0,
                          (struct sockaddr*)&client_addr, &len);

      if (n < 0) {
        perror("recvfrom failed");
        continue;
      }
      
      if (std::string(buffer, n) == "DISCOVER_SERVER") {
        std::cout << "Discovery request received\n";
        
        std::string response = "PORT:" + std::to_string(actual_port);
        ssize_t sent = sendto(udp_sock, response.c_str(), response.size(), 0,
              (struct sockaddr*)&client_addr, len);

        if (sent < 0) {
          perror("sendto failed");
        }
      }
    }

    close(udp_sock);  
  }
}
