#include "kairc/discovery.hpp"

#include "kairc/codec.hpp"

#include <algorithm>
#include <charconv>
#include <limits>

namespace kairc {

namespace {

constexpr std::array<Byte, 8> kPeerRecordMagic{'K', 'A', 'I', 'R', 'C', 'D', 'R', '1'};
constexpr std::uint16_t kPeerRecordVersion = 1;
constexpr std::uint16_t kPeerProtocolVersion = 3;
constexpr std::uint64_t kKnownCapabilities = kPeerCapabilityEventGossip;

void validate_shape(const PeerRecord &record) {
    if (record.sequence == 0) {
        throw Error("peer record sequence must be non-zero");
    }
    if (record.issued_at >= record.expires_at ||
        record.expires_at - record.issued_at > kPeerRecordMaximumLifetimeSeconds) {
        throw Error("peer record has an invalid lifetime");
    }
    if ((record.capabilities & ~kKnownCapabilities) != 0) {
        throw Error("peer record advertises unknown capabilities");
    }
    if (record.endpoints.size() > kMaximumPeerRecordEndpoints) {
        throw Error("peer record advertises too many endpoints");
    }
    if (record.kind != PeerRecordKind::live && record.kind != PeerRecordKind::tombstone) {
        throw Error("peer record has an unknown kind");
    }
    if (record.kind == PeerRecordKind::tombstone) {
        if (!record.endpoints.empty() || record.capabilities != 0) {
            throw Error("peer record tombstone must not advertise capabilities");
        }
        return;
    }
    if (record.endpoints.size() != 1) {
        throw Error("live peer record must contain exactly one endpoint");
    }
    if ((record.capabilities & kPeerCapabilityEventGossip) == 0) {
        throw Error("peer record endpoint has no supported gossip capability");
    }
    for (const OnionEndpoint &endpoint : record.endpoints) {
        if (!is_canonical_onion_v3(endpoint.host) || endpoint.port == 0) {
            throw Error("peer record contains a non-canonical onion endpoint");
        }
    }
    if (!std::is_sorted(record.endpoints.begin(), record.endpoints.end()) ||
        std::adjacent_find(record.endpoints.begin(), record.endpoints.end()) !=
            record.endpoints.end()) {
        throw Error("peer record endpoints are not canonical");
    }
}

int compare_distance(const Hash &left, const Hash &right, const Hash &target) {
    for (std::size_t index = 0; index < target.size(); ++index) {
        const Byte left_distance = static_cast<Byte>(left[index] ^ target[index]);
        const Byte right_distance = static_cast<Byte>(right[index] ^ target[index]);
        if (left_distance < right_distance) {
            return -1;
        }
        if (left_distance > right_distance) {
            return 1;
        }
    }
    return 0;
}

} // namespace

bool is_canonical_onion_v3(std::string_view host) {
    constexpr std::string_view suffix = ".onion";
    constexpr std::size_t label_size = 56;
    if (host.size() != label_size + suffix.size() || !host.ends_with(suffix)) {
        return false;
    }
    return std::all_of(host.begin(), host.begin() + static_cast<std::ptrdiff_t>(label_size),
                       [](char value) {
                           return (value >= 'a' && value <= 'z') || (value >= '2' && value <= '7');
                       });
}

OnionEndpoint parse_advertised_peer_uri(std::string_view uri) {
    constexpr std::string_view prefix = "tor://";
    if (!uri.starts_with(prefix)) {
        throw Error("advertised peers must use tor:// onion-v3 endpoints");
    }
    const std::string_view address = uri.substr(prefix.size());
    const auto colon = address.rfind(':');
    if (colon == std::string_view::npos || address.find(':') != colon) {
        throw Error("advertised peer must use tor://host:port");
    }
    OnionEndpoint endpoint;
    endpoint.host = std::string(address.substr(0, colon));
    if (!is_canonical_onion_v3(endpoint.host)) {
        throw Error("advertised peer must contain a canonical onion-v3 hostname");
    }
    const std::string_view port_text = address.substr(colon + 1);
    unsigned int port = 0;
    const auto [end, error] =
        std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (error != std::errc{} || end != port_text.data() + port_text.size() || port == 0 ||
        port > std::numeric_limits<std::uint16_t>::max()) {
        throw Error("advertised peer has an invalid TCP port");
    }
    endpoint.port = static_cast<std::uint16_t>(port);
    return endpoint;
}

std::string advertised_peer_uri(const OnionEndpoint &endpoint) {
    if (!is_canonical_onion_v3(endpoint.host) || endpoint.port == 0) {
        throw Error("cannot encode a non-canonical onion endpoint");
    }
    return "tor://" + endpoint.host + ':' + std::to_string(endpoint.port);
}

Hash peer_node_id(const Hash &network, const PublicKey &identity) {
    return crypto::hash("kairc/kad-node-id/v1", {network, identity});
}

PeerRecord PeerRecord::create(const Hash &network, const crypto::Identity &identity,
                              std::uint64_t sequence, std::uint64_t issued_at,
                              std::uint64_t expires_at, std::uint64_t capabilities,
                              std::vector<OnionEndpoint> endpoints) {
    std::sort(endpoints.begin(), endpoints.end());
    endpoints.erase(std::unique(endpoints.begin(), endpoints.end()), endpoints.end());
    PeerRecord record{
        .network = network,
        .identity = identity.public_key,
        .kind = endpoints.empty() ? PeerRecordKind::tombstone : PeerRecordKind::live,
        .sequence = sequence,
        .issued_at = issued_at,
        .expires_at = expires_at,
        .capabilities = capabilities,
        .endpoints = std::move(endpoints),
    };
    validate_shape(record);
    record.signature = identity.sign(record.digest());
    return record;
}

PeerRecord PeerRecord::deserialize(std::span<const Byte> wire) {
    if (wire.size() > kMaximumPeerRecordSize) {
        throw Error("peer record exceeds its size limit");
    }
    Reader reader(wire);
    const auto magic = reader.raw(kPeerRecordMagic.size());
    if (!std::equal(magic.begin(), magic.end(), kPeerRecordMagic.begin()) ||
        reader.u16() != kPeerRecordVersion) {
        throw Error("peer record has an invalid magic or version");
    }
    PeerRecord record;
    record.kind = static_cast<PeerRecordKind>(reader.u8());
    record.network = reader.fixed<32>("peer record network");
    record.identity = reader.fixed<32>("peer record identity");
    record.sequence = reader.u64();
    record.issued_at = reader.u64();
    record.expires_at = reader.u64();
    if (reader.u16() != kPeerProtocolVersion) {
        throw Error("peer record advertises an incompatible P2P protocol");
    }
    record.capabilities = reader.u64();
    const std::size_t endpoint_count = reader.u8();
    if (endpoint_count > kMaximumPeerRecordEndpoints) {
        throw Error("peer record advertises too many endpoints");
    }
    record.endpoints.reserve(endpoint_count);
    for (std::size_t index = 0; index < endpoint_count; ++index) {
        record.endpoints.push_back(OnionEndpoint{reader.string(128), reader.u16()});
    }
    record.signature = reader.fixed<64>("peer record signature");
    if (!reader.empty()) {
        throw Error("peer record has trailing bytes");
    }
    validate_shape(record);
    return record;
}

Bytes PeerRecord::unsigned_bytes() const {
    if (endpoints.size() > kMaximumPeerRecordEndpoints) {
        throw Error("peer record advertises too many endpoints");
    }
    Writer writer;
    writer.raw(kPeerRecordMagic);
    writer.u16(kPeerRecordVersion);
    writer.u8(static_cast<std::uint8_t>(kind));
    writer.fixed(network);
    writer.fixed(identity);
    writer.u64(sequence);
    writer.u64(issued_at);
    writer.u64(expires_at);
    writer.u16(kPeerProtocolVersion);
    writer.u64(capabilities);
    writer.u8(static_cast<std::uint8_t>(endpoints.size()));
    for (const OnionEndpoint &endpoint : endpoints) {
        writer.string(endpoint.host);
        writer.u16(endpoint.port);
    }
    return std::move(writer).take();
}

Bytes PeerRecord::serialize() const {
    validate_shape(*this);
    Writer writer;
    writer.raw(unsigned_bytes());
    writer.fixed(signature);
    Bytes wire = std::move(writer).take();
    if (wire.size() > kMaximumPeerRecordSize) {
        throw Error("peer record exceeds its size limit");
    }
    return wire;
}

Hash PeerRecord::digest() const {
    const Bytes canonical = unsigned_bytes();
    return crypto::hash("kairc/peer-record/v1", canonical);
}

Hash PeerRecord::id() const {
    const Bytes wire = serialize();
    return crypto::hash("kairc/peer-record-id/v1", wire);
}

Hash PeerRecord::node_id() const {
    return peer_node_id(network, identity);
}

bool PeerRecord::tombstone() const noexcept {
    return kind == PeerRecordKind::tombstone;
}

bool PeerRecord::time_window_is_valid(std::uint64_t now_seconds) const noexcept {
    if (issued_at > now_seconds && issued_at - now_seconds > kPeerRecordFutureSkewSeconds) {
        return false;
    }
    if (expires_at <= now_seconds) {
        return false;
    }
    return expires_at - now_seconds <=
           kPeerRecordMaximumLifetimeSeconds + kPeerRecordFutureSkewSeconds;
}

void PeerRecord::precheck(const Hash &expected_network, std::uint64_t now_seconds) const {
    validate_shape(*this);
    if (network != expected_network) {
        throw Error("peer record belongs to another network");
    }
    if (!time_window_is_valid(now_seconds)) {
        throw Error("peer record is outside the accepted time window");
    }
}

void PeerRecord::verify_signature() const {
    if (!crypto::verify(identity, digest(), signature)) {
        throw Error("peer record signature is invalid");
    }
}

void PeerRecord::validate(const Hash &expected_network, std::uint64_t now_seconds) const {
    precheck(expected_network, now_seconds);
    verify_signature();
}

PeerDirectory::PeerDirectory(Hash network, PublicKey local_identity)
    : network_(network), local_identity_(local_identity),
      local_node_id_(peer_node_id(network_, local_identity_)) {}

std::optional<PeerRecordInsertStatus> PeerDirectory::classify(const PeerRecord &record,
                                                              std::uint64_t now_seconds) {
    record.precheck(network_, now_seconds);
    if (record.identity == local_identity_) {
        return PeerRecordInsertStatus::local_identity;
    }
    auto &bucket = buckets_[bucket_for(record.identity)];
    prune_bucket(bucket, now_seconds);
    const auto classify_entries =
        [&](const std::vector<Entry> &entries) -> std::optional<PeerRecordInsertStatus> {
        const auto existing = std::find_if(entries.begin(), entries.end(), [&](const Entry &entry) {
            return entry.record.identity == record.identity;
        });
        if (existing == entries.end()) {
            return std::nullopt;
        }
        if (record.sequence < existing->record.sequence) {
            return PeerRecordInsertStatus::stale;
        }
        if (record.sequence == existing->record.sequence) {
            return record.serialize() == existing->record.serialize()
                       ? PeerRecordInsertStatus::duplicate
                       : PeerRecordInsertStatus::equivocation;
        }
        return std::nullopt;
    };
    if (const auto status = classify_entries(bucket.primary)) {
        return status;
    }
    return classify_entries(bucket.replacements);
}

PeerRecordInsertStatus PeerDirectory::preview_insert(const PeerRecord &record,
                                                     std::uint64_t now_seconds,
                                                     PeerRecordAdmission admission) {
    if (const auto status = classify(record, now_seconds)) {
        return *status;
    }
    auto &bucket = buckets_[bucket_for(record.identity)];
    const auto find_identity = [&](std::vector<Entry> &entries) {
        return std::find_if(entries.begin(), entries.end(), [&](const Entry &entry) {
            return entry.record.identity == record.identity;
        });
    };
    const auto primary = find_identity(bucket.primary);
    const auto replacement = find_identity(bucket.replacements);
    const bool exists = primary != bucket.primary.end() || replacement != bucket.replacements.end();
    const bool anchored =
        admission.identity_anchored || admission.endpoint_verified ||
        (primary != bucket.primary.end() && primary->withdrawal_anchored) ||
        (replacement != bucket.replacements.end() && replacement->withdrawal_anchored);
    // A withdrawal only has meaning after this identity completed an exact-key
    // endpoint handshake, either in this process or in persisted state.
    // Otherwise zero-reachability Sybils could fill replacement buckets and
    // discovery responses with self-signed tombstones.
    if (record.tombstone() && !anchored) {
        return PeerRecordInsertStatus::unanchored_tombstone;
    }
    if (exists) {
        return PeerRecordInsertStatus::updated;
    }
    if (admission.endpoint_verified && bucket.primary.size() < kBucketCapacity) {
        return PeerRecordInsertStatus::inserted;
    }
    if (bucket.replacements.size() < kBucketCapacity) {
        return PeerRecordInsertStatus::inserted;
    }
    if (admission.priority != PeerRecordPriority::ordinary &&
        std::any_of(bucket.replacements.begin(), bucket.replacements.end(),
                    [&](const Entry &entry) { return entry.priority < admission.priority; })) {
        return PeerRecordInsertStatus::inserted;
    }
    return PeerRecordInsertStatus::bucket_full;
}

PeerRecordInsertStatus PeerDirectory::insert(const PeerRecord &record, std::uint64_t now_seconds,
                                             PeerRecordAdmission admission) {
    const PeerRecordInsertStatus preview = preview_insert(record, now_seconds, admission);
    if (preview != PeerRecordInsertStatus::inserted && preview != PeerRecordInsertStatus::updated) {
        return preview;
    }
    record.verify_signature();
    return insert_verified(record, now_seconds, admission);
}

PeerRecordInsertStatus PeerDirectory::insert_verified(const PeerRecord &record,
                                                      std::uint64_t now_seconds,
                                                      PeerRecordAdmission admission) {
    const PeerRecordInsertStatus preview = preview_insert(record, now_seconds, admission);
    if (preview != PeerRecordInsertStatus::inserted && preview != PeerRecordInsertStatus::updated) {
        return preview;
    }
    auto &bucket = buckets_[bucket_for(record.identity)];
    const auto update_existing = [&](std::vector<Entry> &entries,
                                     bool was_primary) -> std::optional<PeerRecordInsertStatus> {
        const auto existing = std::find_if(entries.begin(), entries.end(), [&](const Entry &entry) {
            return entry.record.identity == record.identity;
        });
        if (existing == entries.end()) {
            return std::nullopt;
        }
        const bool same_endpoint = existing->record.kind == record.kind &&
                                   existing->record.capabilities == record.capabilities &&
                                   existing->record.endpoints == record.endpoints;
        const bool remains_verified =
            admission.endpoint_verified || (existing->endpoint_verified && same_endpoint);
        const bool remains_anchored = admission.identity_anchored || admission.endpoint_verified ||
                                      existing->withdrawal_anchored;
        // Priority is a property of this admission (configured trusted subject,
        // or this specific anchored withdrawal), never a sticky identity bit.
        const PeerRecordPriority remains_priority = admission.priority;
        entries.erase(existing);
        Entry replacement =
            make_entry(record, now_seconds, remains_verified, remains_anchored, remains_priority);
        if (remains_verified && !record.tombstone() &&
            (was_primary || bucket.primary.size() < kBucketCapacity)) {
            bucket.primary.push_back(std::move(replacement));
        } else {
            if (bucket.replacements.size() >= kBucketCapacity) {
                auto eviction = bucket.replacements.end();
                for (auto candidate = bucket.replacements.begin();
                     candidate != bucket.replacements.end(); ++candidate) {
                    if (candidate->priority < remains_priority &&
                        (eviction == bucket.replacements.end() ||
                         candidate->priority < eviction->priority ||
                         (candidate->priority == eviction->priority &&
                          candidate->deadline < eviction->deadline))) {
                        eviction = candidate;
                    }
                }
                if (eviction == bucket.replacements.end()) {
                    // The durable high-water was already advanced by the caller.
                    // Drop this untrusted cache entry instead of evicting priority state.
                    return PeerRecordInsertStatus::updated;
                }
                bucket.replacements.erase(eviction);
            }
            bucket.replacements.push_back(std::move(replacement));
        }
        return PeerRecordInsertStatus::updated;
    };
    if (const auto status = update_existing(bucket.primary, true)) {
        return *status;
    }
    if (const auto status = update_existing(bucket.replacements, false)) {
        return *status;
    }

    Entry entry = make_entry(record, now_seconds, admission.endpoint_verified,
                             admission.identity_anchored, admission.priority);
    if (admission.endpoint_verified && !record.tombstone() &&
        bucket.primary.size() < kBucketCapacity) {
        bucket.primary.push_back(std::move(entry));
    } else {
        if (bucket.replacements.size() >= kBucketCapacity) {
            if (admission.priority == PeerRecordPriority::ordinary) {
                return PeerRecordInsertStatus::bucket_full;
            }
            auto eviction = bucket.replacements.end();
            for (auto candidate = bucket.replacements.begin();
                 candidate != bucket.replacements.end(); ++candidate) {
                if (candidate->priority < admission.priority &&
                    (eviction == bucket.replacements.end() ||
                     candidate->priority < eviction->priority ||
                     (candidate->priority == eviction->priority &&
                      candidate->deadline < eviction->deadline))) {
                    eviction = candidate;
                }
            }
            if (eviction == bucket.replacements.end()) {
                return PeerRecordInsertStatus::bucket_full;
            }
            bucket.replacements.erase(eviction);
        }
        bucket.replacements.push_back(std::move(entry));
    }
    return PeerRecordInsertStatus::inserted;
}

bool PeerDirectory::mark_verified(const PublicKey &identity, std::uint64_t sequence,
                                  std::uint64_t now_seconds) {
    if (identity == local_identity_) {
        return false;
    }
    auto &bucket = buckets_[bucket_for(identity)];
    prune_bucket(bucket, now_seconds);
    const auto primary =
        std::find_if(bucket.primary.begin(), bucket.primary.end(), [&](const Entry &entry) {
            return entry.record.identity == identity && entry.record.sequence == sequence &&
                   !entry.record.tombstone();
        });
    if (primary != bucket.primary.end()) {
        primary->endpoint_verified = true;
        primary->withdrawal_anchored = true;
        return true;
    }
    const auto replacement = std::find_if(
        bucket.replacements.begin(), bucket.replacements.end(), [&](const Entry &entry) {
            return entry.record.identity == identity && entry.record.sequence == sequence &&
                   !entry.record.tombstone();
        });
    if (replacement == bucket.replacements.end()) {
        return false;
    }
    replacement->endpoint_verified = true;
    replacement->withdrawal_anchored = true;
    if (bucket.primary.size() < kBucketCapacity) {
        bucket.primary.push_back(std::move(*replacement));
        bucket.replacements.erase(replacement);
    } else if (replacement->priority == PeerRecordPriority::trusted) {
        const auto eviction =
            std::find_if(bucket.primary.begin(), bucket.primary.end(), [](const Entry &entry) {
                return entry.priority < PeerRecordPriority::trusted;
            });
        if (eviction != bucket.primary.end()) {
            bucket.primary.erase(eviction);
            bucket.primary.push_back(std::move(*replacement));
            bucket.replacements.erase(replacement);
        }
    }
    return true;
}

std::optional<PeerRecord> PeerDirectory::find(const PublicKey &identity,
                                              std::uint64_t now_seconds) {
    if (identity == local_identity_) {
        return std::nullopt;
    }
    auto &bucket = buckets_[bucket_for(identity)];
    prune_bucket(bucket, now_seconds);
    for (const auto *entries : {&bucket.primary, &bucket.replacements}) {
        const auto found = std::find_if(entries->begin(), entries->end(), [&](const Entry &entry) {
            return entry.record.identity == identity;
        });
        if (found != entries->end()) {
            return found->record.tombstone() ? std::nullopt
                                             : std::optional<PeerRecord>(found->record);
        }
    }
    return std::nullopt;
}

std::vector<PeerRecord> PeerDirectory::closest(const Hash &target, std::size_t limit,
                                               std::uint64_t now_seconds) {
    prune(now_seconds);
    std::vector<PeerRecord> records;
    records.reserve(size());
    for (const auto &bucket : buckets_) {
        for (const Entry &entry : bucket.primary) {
            if (entry.endpoint_verified && !entry.record.tombstone()) {
                records.push_back(entry.record);
            }
        }
        for (const Entry &entry : bucket.replacements) {
            if (entry.record.tombstone() || entry.endpoint_verified) {
                records.push_back(entry.record);
            }
        }
    }
    std::sort(records.begin(), records.end(), [&](const PeerRecord &left, const PeerRecord &right) {
        return peer_record_distance_less(left, right, target);
    });
    if (records.size() > limit) {
        records.resize(limit);
    }
    return records;
}

std::vector<PeerRecord> PeerDirectory::dial_candidates(const Hash &target, std::size_t limit,
                                                       std::uint64_t now_seconds) {
    prune(now_seconds);
    std::vector<PeerRecord> records;
    records.reserve(size());
    for (const auto &bucket : buckets_) {
        for (const auto *entries : {&bucket.primary, &bucket.replacements}) {
            for (const Entry &entry : *entries) {
                if (!entry.record.tombstone()) {
                    records.push_back(entry.record);
                }
            }
        }
    }
    std::sort(records.begin(), records.end(), [&](const PeerRecord &left, const PeerRecord &right) {
        return peer_record_distance_less(left, right, target);
    });
    if (records.size() > limit) {
        records.resize(limit);
    }
    return records;
}

void PeerDirectory::erase(const PublicKey &identity) {
    if (identity == local_identity_) {
        return;
    }
    auto &bucket = buckets_[bucket_for(identity)];
    const auto remove = [&](std::vector<Entry> &entries) {
        std::erase_if(entries,
                      [&](const Entry &entry) { return entry.record.identity == identity; });
    };
    remove(bucket.primary);
    remove(bucket.replacements);
}

void PeerDirectory::prune(std::uint64_t now_seconds) {
    for (auto &bucket : buckets_) {
        prune_bucket(bucket, now_seconds);
    }
}

std::size_t PeerDirectory::size() const noexcept {
    std::size_t total = 0;
    for (const auto &bucket : buckets_) {
        total += bucket.primary.size() + bucket.replacements.size();
    }
    return total;
}

const Hash &PeerDirectory::local_node_id() const noexcept {
    return local_node_id_;
}

PeerDirectory::Entry PeerDirectory::make_entry(const PeerRecord &record, std::uint64_t now_seconds,
                                               bool endpoint_verified, bool identity_anchored,
                                               PeerRecordPriority priority) {
    if (record.expires_at <= now_seconds) {
        throw Error("cannot cache an expired peer record");
    }
    const auto remaining = std::chrono::seconds(record.expires_at - now_seconds);
    return Entry{
        .record = record,
        .endpoint_verified = endpoint_verified && !record.tombstone(),
        .withdrawal_anchored = identity_anchored || endpoint_verified,
        .priority = priority,
        .deadline = std::chrono::steady_clock::now() + remaining,
    };
}

void PeerDirectory::prune_bucket(Bucket &bucket, std::uint64_t now_seconds) {
    const auto monotonic_now = std::chrono::steady_clock::now();
    const auto expired = [now_seconds, monotonic_now](const Entry &entry) {
        // The steady deadline prevents a wall-clock rollback from extending a
        // record.  The signed absolute expiry must also win after a clock jump.
        return entry.record.expires_at <= now_seconds || entry.deadline <= monotonic_now;
    };
    std::erase_if(bucket.primary, expired);
    std::erase_if(bucket.replacements, expired);
    while (bucket.primary.size() < kBucketCapacity) {
        auto replacement = std::find_if(
            bucket.replacements.begin(), bucket.replacements.end(), [](const Entry &entry) {
                return entry.priority == PeerRecordPriority::trusted && entry.endpoint_verified &&
                       !entry.record.tombstone();
            });
        if (replacement == bucket.replacements.end()) {
            replacement = std::find_if(
                bucket.replacements.begin(), bucket.replacements.end(), [](const Entry &entry) {
                    return entry.endpoint_verified && !entry.record.tombstone();
                });
        }
        if (replacement == bucket.replacements.end()) {
            break;
        }
        bucket.primary.push_back(std::move(*replacement));
        bucket.replacements.erase(replacement);
    }
}

std::size_t PeerDirectory::bucket_for(const PublicKey &identity) const {
    const Hash candidate = peer_node_id(network_, identity);
    std::size_t leading_zero_bits = 0;
    for (std::size_t index = 0; index < candidate.size(); ++index) {
        const Byte distance = static_cast<Byte>(candidate[index] ^ local_node_id_[index]);
        if (distance == 0) {
            leading_zero_bits += 8;
            continue;
        }
        for (int bit = 7; bit >= 0; --bit) {
            if ((distance & static_cast<Byte>(1U << bit)) != 0) {
                return 255 - leading_zero_bits;
            }
            ++leading_zero_bits;
        }
    }
    throw Error("local peer identity cannot occupy its own routing bucket");
}

bool peer_record_distance_less(const PeerRecord &left, const PeerRecord &right,
                               const Hash &target) {
    const Hash left_id = left.node_id();
    const Hash right_id = right.node_id();
    const int comparison = compare_distance(left_id, right_id, target);
    if (comparison != 0) {
        return comparison < 0;
    }
    return left.identity < right.identity;
}

} // namespace kairc
