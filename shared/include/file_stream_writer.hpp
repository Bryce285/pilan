#include <unistd.h>
#include <errno.h>
#include <stdexcept>
#include <system_error>
#include "stream_writer.hpp"

#pragma once

class FileStreamWriter : public StreamWriter {
    public:
        explicit FileStreamWriter(int file_dscrpt)
            : fd(file_dscrpt) {}

        void write(const uint8_t* data, size_t len) override {
            size_t total = 0;

            while (total < len) {
                ssize_t result = ::write(fd, data + total, len - total);
                if (result < 0) {
                    if (errno == EINTR)
                        continue;

                    throw std::system_error(
                            errno,
                            std::generic_category(),
                            "FileStreamWriter write failed"
                    );
                }

                if (result == 0) {
                    throw std::runtime_error("Write returned 0 bytes");
                }

                total += static_cast<size_t>(result);
            }
        }

        void flush() override {}

    private:
        int fd;
};
