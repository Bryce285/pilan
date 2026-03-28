#include "discovery_client.hpp"

#include <iostream>
#include <asm-generic/socket.h>
#include <limits>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdexcept>
#include <unistd.h>

namespace DiscoveryClient
{
  void discover(ServerInfo& serv_info_out)
  {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
      perror("socket failed");
      throw std::runtime_error("socket failed");
    }
    
    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
      perror("setsockopt broadcast failed");
      close(sock);
      throw std::runtime_error("setsockopt failed");
    }

    
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(0);
    local.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
      perror("bind failed");
      close(sock);
      throw std::runtime_error("bind failed");
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    addr.sin_addr.s_addr = inet_addr("255.255.255.255");

    const char* msg = "DISCOVER_SERVER";

    ssize_t sent = sendto(sock, msg, strlen(msg), 0,
          (struct sockaddr*)&addr, sizeof(addr));

    if (sent < 0) {
      perror("sendto failed");
      close(sock);
      throw std::runtime_error("sendto failed");
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    
    timeval tv{};
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    // need to use select() because of compile issues with SO_RCVTIMEO 
    int ret = select(sock + 1, &fds, nullptr, nullptr, &tv);

    if (ret < 0) {
      perror("select failed");
      close(sock);
      throw std::runtime_error("select failed");
    }

    if (ret == 0) {
      std::cout << "Discovery timeout (no server found)\n";
      close(sock);
      return;
    }
    
    char buffer[1024];
    sockaddr_in serv_addr;
    socklen_t len = sizeof(serv_addr);

    ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0,
                        (struct sockaddr*)&serv_addr, &len);

    if (n < 0) {
      perror("recvfrom failed (timeout likely)");
      close(sock);
      return;
    }
    
    if (std::string(buffer, n).starts_with("PORT:")) {
      std::string data = std::string(buffer, n);
      data.erase(0, 5);      

      int value = std::stoi(data);

      if (value < std::numeric_limits<uint16_t>::min() || value > std::numeric_limits<uint16_t>::max()) {
        throw std::runtime_error("Invalid port received from server: " + std::to_string(value));
      }

      serv_info_out.server_addr = serv_addr;
      serv_info_out.port = static_cast<uint16_t>(value);
      serv_info_out.discovery_success = true;

      std::cout << "Server found at " << inet_ntoa(serv_addr.sin_addr)
                << ":" << value << std::endl;
    }

    close(sock);
  }
}
