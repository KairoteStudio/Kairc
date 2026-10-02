#pragma once

#include "kairc/crypto.hpp"

#include <string>

namespace kairc {

inline constexpr std::uint8_t kEventVersion = 2;
inline constexpr std::uint64_t kEpochMilliseconds = 60ULL * 60ULL * 1000ULL;
inline constexpr std::size_t kMaxEventParents = 4;
inline constexpr std::size_t kMaxEventContent = 8192;

enum class EventKind : std::uint8_t {
    channel_message = 1,
};

struct Event {
    std::uint8_t version = kEventVersion;
    EventKind kind = EventKind::channel_message;
    Hash network{};
    std::uint64_t timestamp_ms = 0;
    PublicKey author{};
    std::uint64_t work_nonce = 0;
    std::vector<Hash> parents;
    Hash channel{};
    Nonce content_nonce{};
    Bytes content;
    Signature signature{};
    Hash id{};

    std::uint64_t epoch() const noexcept {
        return timestamp_ms / kEpochMilliseconds;
    }
    Bytes payload_context() const;
    Bytes unsigned_bytes() const;
    Bytes serialize() const;
    static Event deserialize(std::span<const Byte> bytes);

    void seal(const crypto::Identity &identity, std::uint8_t work_bits);
    bool verify(const Hash &expected_network, std::uint8_t work_bits, std::uint64_t now_ms,
                std::string *error = nullptr) const;
    Hash calculate_id() const;
};

Hash network_hash(std::string_view network_id, std::uint8_t work_bits);
Hash epoch_root(const Hash &network, std::uint64_t epoch);

} // namespace kairc
