#pragma once

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace cryptofuzz {
namespace util {

std::string HexDump(const void *_data, const size_t len, const std::string description = "");
std::string HexDump(std::vector<uint8_t> data, const std::string description = "");

} /* namespace util */
} /* namespace cryptofuzz */
