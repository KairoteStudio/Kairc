#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kairc {

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using Hash = std::array<Byte, 32>;
using PublicKey = std::array<Byte, 32>;
using SecretKey = std::array<Byte, 64>;
using Signature = std::array<Byte, 64>;
using Key = std::array<Byte, 32>;
using Nonce = std::array<Byte, 24>;

class Error : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

std::string hex(std::span<const Byte> data);
Bytes unhex(std::string_view text);
std::uint64_t unix_time_ms();

struct HashHasher {
    std::size_t operator()(const Hash &value) const noexcept;
};

template <std::size_t N>
std::array<Byte, N> fixed_bytes(std::span<const Byte> value, std::string_view label) {
    if (value.size() != N) {
        throw Error(std::string(label) + " has the wrong length");
    }
    std::array<Byte, N> output{};
    std::copy(value.begin(), value.end(), output.begin());
    return output;
}

template <std::size_t N> std::string hex(const std::array<Byte, N> &value) {
    return hex(std::span<const Byte>(value));
}

} // namespace kairc
