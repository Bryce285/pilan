#include <chrono>

#pragma once

namespace Utils
{
    uint64_t ServerStorageManager::unix_timestamp_ms()
    {
	    using namespace std::chrono;
        return duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        ).count();
    }
}
