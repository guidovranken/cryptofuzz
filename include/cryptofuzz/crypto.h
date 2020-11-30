#pragma once

#include <cstdint>
#include <vector>

namespace cryptofuzz {
namespace crypto {

std::vector<uint8_t> sha1(const uint8_t* data, const size_t size);
std::vector<uint8_t> sha1(const std::vector<uint8_t> data);

std::vector<uint8_t> sha256(const uint8_t* data, const size_t size);
std::vector<uint8_t> sha256(const std::vector<uint8_t> data);

std::vector<uint8_t> hmac_sha256(const uint8_t* data, const size_t size, const uint8_t* key, const size_t key_size);
std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t> data, const std::vector<uint8_t> key);

} /* namespace crypto */
} /* namespace cryptofuzz */
