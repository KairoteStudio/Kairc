#include "kairc/types.hpp"

#include <algorithm>
#include <chrono>

namespace kairc {

namespace {

int nibble(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

} // namespace

std::string hex(std::span<const Byte> data) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string output(data.size() * 2, '0');
    for (std::size_t i = 0; i < data.size(); ++i) {
        output[i * 2] = alphabet[data[i] >> 4U];
        output[i * 2 + 1] = alphabet[data[i] & 0x0fU];
    }
    return output;
}

Bytes unhex(std::string_view text) {
    if (text.size() % 2 != 0) {
        throw Error("hex value must contain an even number of characters");
    }
    Bytes output(text.size() / 2);
    for (std::size_t i = 0; i < output.size(); ++i) {
        const int high = nibble(text[i * 2]);
        const int low = nibble(text[i * 2 + 1]);
        if (high < 0 || low < 0) {
            throw Error("hex value contains a non-hexadecimal character");
        }
        output[i] = static_cast<Byte>((high << 4U) | low);
    }
    return output;
}

std::uint64_t unix_time_ms() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

std::size_t HashHasher::operator()(const Hash &value) const noexcept {
    std::size_t result = 0xcbf29ce484222325ULL;
    for (const Byte byte : value) {
        result ^= byte;
        result *= 0x100000001b3ULL;
    }
    return result;
}

} // namespace kairc
