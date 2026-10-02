#include "kairc/event.hpp"

#include "kairc/codec.hpp"

#include <algorithm>
#include <limits>
#include <unordered_set>

namespace kairc {

namespace {

constexpr std::uint64_t kMaximumFutureDriftMs = 5ULL * 60ULL * 1000ULL;

void set_error(std::string *error, std::string message) {
    if (error != nullptr) {
        *error = std::move(message);
    }
}

Hash signing_digest(const Event &event) {
    const Bytes bytes = event.unsigned_bytes();
    return crypto::hash("kairc/event-signature/v1", bytes);
}

Hash work_digest(const Event &event) {
    const Bytes bytes = event.unsigned_bytes();
    return crypto::hash("kairc/event-work/v1", bytes);
}

} // namespace

Bytes Event::payload_context() const {
    if (parents.empty() || parents.size() > kMaxEventParents) {
        throw Error("event must have between one and four parents");
    }
    Writer writer;
    writer.u8(version);
    writer.u8(static_cast<std::uint8_t>(kind));
    writer.fixed(network);
    writer.u64(timestamp_ms);
    writer.fixed(author);
    writer.u8(static_cast<std::uint8_t>(parents.size()));
    for (const Hash &parent : parents) {
        writer.fixed(parent);
    }
    writer.fixed(channel);
    return std::move(writer).take();
}

Bytes Event::unsigned_bytes() const {
    if (parents.empty() || parents.size() > kMaxEventParents) {
        throw Error("event must have between one and four parents");
    }
    if (content.size() > kMaxEventContent) {
        throw Error("event content exceeds the protocol limit");
    }

    Writer writer;
    writer.u8(version);
    writer.u8(static_cast<std::uint8_t>(kind));
    writer.fixed(network);
    writer.u64(timestamp_ms);
    writer.fixed(author);
    writer.u64(work_nonce);
    writer.u8(static_cast<std::uint8_t>(parents.size()));
    for (const Hash &parent : parents) {
        writer.fixed(parent);
    }
    writer.fixed(channel);
    writer.fixed(content_nonce);
    writer.bytes(content);
    return std::move(writer).take();
}

Bytes Event::serialize() const {
    Writer writer;
    writer.raw(unsigned_bytes());
    writer.fixed(signature);
    return std::move(writer).take();
}

Event Event::deserialize(std::span<const Byte> bytes) {
    if (bytes.size() > kMaxEventContent + 512) {
        throw Error("serialized event exceeds the protocol limit");
    }
    Reader reader(bytes);
    Event event;
    event.version = reader.u8();
    event.kind = static_cast<EventKind>(reader.u8());
    event.network = reader.fixed<32>("network hash");
    event.timestamp_ms = reader.u64();
    event.author = reader.fixed<32>("author key");
    event.work_nonce = reader.u64();
    const std::size_t parent_count = reader.u8();
    if (parent_count == 0 || parent_count > kMaxEventParents) {
        throw Error("invalid event parent count");
    }
    event.parents.reserve(parent_count);
    for (std::size_t i = 0; i < parent_count; ++i) {
        event.parents.push_back(reader.fixed<32>("parent hash"));
    }
    event.channel = reader.fixed<32>("channel tag");
    event.content_nonce = reader.fixed<24>("content nonce");
    event.content = reader.bytes(kMaxEventContent);
    event.signature = reader.fixed<64>("event signature");
    if (!reader.empty()) {
        throw Error("event has trailing bytes");
    }
    event.id = event.calculate_id();
    return event;
}

void Event::seal(const crypto::Identity &identity, std::uint8_t work_bits) {
    author = identity.public_key;
    if (work_bits > 24) {
        throw Error("proof-of-work above 24 bits is refused by this implementation");
    }
    for (;;) {
        if (crypto::has_leading_zero_bits(work_digest(*this), work_bits)) {
            break;
        }
        if (work_nonce == std::numeric_limits<std::uint64_t>::max()) {
            throw Error("proof-of-work nonce space exhausted");
        }
        ++work_nonce;
    }
    const Hash digest = signing_digest(*this);
    signature = identity.sign(digest);
    id = calculate_id();
}

bool Event::verify(const Hash &expected_network, std::uint8_t work_bits, std::uint64_t now_ms,
                   std::string *error) const {
    if (version != kEventVersion) {
        set_error(error, "unsupported event version");
        return false;
    }
    if (kind != EventKind::channel_message) {
        set_error(error, "unsupported event kind");
        return false;
    }
    if (network != expected_network) {
        set_error(error, "event belongs to another network");
        return false;
    }
    if (timestamp_ms == 0 || timestamp_ms > now_ms + kMaximumFutureDriftMs) {
        set_error(error, "event timestamp is outside the accepted future window");
        return false;
    }
    if (parents.empty() || parents.size() > kMaxEventParents) {
        set_error(error, "invalid event parent count");
        return false;
    }
    if (content.empty() || content.size() > kMaxEventContent) {
        set_error(error, "invalid event content length");
        return false;
    }
    std::unordered_set<Hash, HashHasher> unique;
    for (const Hash &parent : parents) {
        if (!unique.insert(parent).second) {
            set_error(error, "event repeats a parent");
            return false;
        }
    }
    try {
        if (!crypto::has_leading_zero_bits(work_digest(*this), work_bits)) {
            set_error(error, "event proof-of-work is insufficient");
            return false;
        }
        const Hash digest = signing_digest(*this);
        if (!crypto::verify(author, digest, signature)) {
            set_error(error, "event signature is invalid");
            return false;
        }
        if (id != calculate_id()) {
            set_error(error, "event ID does not match its content");
            return false;
        }
    } catch (const Error &exception) {
        set_error(error, exception.what());
        return false;
    }
    return true;
}

Hash Event::calculate_id() const {
    // A signature authenticates these bytes but is not part of event identity.
    // Otherwise an author can reuse one PoW solution with multiple valid Ed25519
    // signatures and defeat content-ID deduplication.
    const Bytes canonical = unsigned_bytes();
    return crypto::hash("kairc/event-id/v2", canonical);
}

Hash network_hash(std::string_view network_id, std::uint8_t work_bits) {
    if (network_id.empty() || network_id.size() > 128) {
        throw Error("network ID must contain between 1 and 128 bytes");
    }
    if (work_bits > 24) {
        throw Error("network work difficulty must be between 0 and 24 bits");
    }
    Writer writer;
    writer.string(network_id);
    writer.u8(work_bits);
    const Bytes parameters = std::move(writer).take();
    return crypto::hash("kairc/network/v2", parameters);
}

Hash epoch_root(const Hash &network, std::uint64_t epoch) {
    Writer writer;
    writer.fixed(network);
    writer.u64(epoch);
    const Bytes input = std::move(writer).take();
    return crypto::hash("kairc/epoch-root/v1", input);
}

} // namespace kairc
