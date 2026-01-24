#include <cstddef>
#include <cstdint>

#pragma once

class StreamWriter
{
	public:
		virtual ~StreamWriter() = default;
		virtual void write(const uint8_t* data, size_t len) = 0;	
		virtual void flush() = 0;
};
