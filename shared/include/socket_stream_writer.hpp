#include "stream_writer.hpp"

#pragma once

class SocketStreamWriter : public StreamWriter {
	public:
		explicit SocketStreamWriter(int sock)
			: fd(sock) {}
		
		void write(const char* data, size_t len) override {
			size_t total = 0;
			while (total < len) {
				ssize_t sent = ::send(fd, data + total, len - total, 0);
				if (sent <= 0) {
					throw std::runtime_error("Socket write failed");
				}

				total += sent;
			}
		}

		void flush() override {}

	private:
		int fd;
};
