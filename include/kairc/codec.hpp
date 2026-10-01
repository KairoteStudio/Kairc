#pragma once

#include "kairc/types.hpp"

#include <algorithm>
#include <limits>

namespace kairc {

class Writer {
  public:
    void u8(std::uint8_t value) {
        data_.push_back(value);
    }

    void u16(std::uint16_t value) {
        data_.push_back(static_cast<Byte>(value >> 8U));
        data_.push_back(static_cast<Byte>(value));
    }

    void u32(std::uint32_t value) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            data_.push_back(static_cast<Byte>(value >> shift));
        }
    }

    void u64(std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            data_.push_back(static_cast<Byte>(value >> shift));
        }
    }

    void raw(std::span<const Byte> value) {
        data_.insert(data_.end(), value.begin(), value.end());
    }

    template <std::size_t N> void fixed(const std::array<Byte, N> &value) {
        raw(value);
    }

    void bytes(std::span<const Byte> value) {
        if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw Error("byte string is too large to encode");
        }
        u32(static_cast<std::uint32_t>(value.size()));
        raw(value);
    }

    void string(std::string_view value) {
        if (value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw Error("string is too large to encode");
        }
        u16(static_cast<std::uint16_t>(value.size()));
        raw(std::span<const Byte>(reinterpret_cast<const Byte *>(value.data()), value.size()));
    }

    const Bytes &view() const noexcept {
        return data_;
    }
    Bytes take() && {
        return std::move(data_);
    }

  private:
    Bytes data_;
};

class Reader {
  public:
    explicit Reader(std::span<const Byte> data) : data_(data) {}

    std::uint8_t u8() {
        require(1);
        return data_[offset_++];
    }

    std::uint16_t u16() {
        require(2);
        const auto value =
            static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[offset_]) << 8U |
                                       static_cast<std::uint16_t>(data_[offset_ + 1]));
        offset_ += 2;
        return value;
    }

    std::uint32_t u32() {
        require(4);
        std::uint32_t value = 0;
        for (int i = 0; i < 4; ++i) {
            value = value << 8U | data_[offset_++];
        }
        return value;
    }

    std::uint64_t u64() {
        require(8);
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
            value = value << 8U | data_[offset_++];
        }
        return value;
    }

    std::span<const Byte> raw(std::size_t size) {
        require(size);
        const auto output = data_.subspan(offset_, size);
        offset_ += size;
        return output;
    }

    template <std::size_t N> std::array<Byte, N> fixed(std::string_view label) {
        return fixed_bytes<N>(raw(N), label);
    }

    Bytes bytes(std::size_t maximum) {
        const std::size_t size = u32();
        if (size > maximum) {
            throw Error("encoded byte string exceeds its limit");
        }
        const auto value = raw(size);
        return Bytes(value.begin(), value.end());
    }

    std::string string(std::size_t maximum) {
        const std::size_t size = u16();
        if (size > maximum) {
            throw Error("encoded string exceeds its limit");
        }
        const auto value = raw(size);
        return std::string(reinterpret_cast<const char *>(value.data()), value.size());
    }

    bool empty() const noexcept {
        return offset_ == data_.size();
    }
    std::size_t remaining() const noexcept {
        return data_.size() - offset_;
    }

  private:
    void require(std::size_t size) const {
        if (size > data_.size() - offset_) {
            throw Error("truncated binary message");
        }
    }

    std::span<const Byte> data_;
    std::size_t offset_ = 0;
};

} // namespace kairc
