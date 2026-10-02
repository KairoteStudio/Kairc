#pragma once

#include "kairc/crypto.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kairc {

enum class DiscoveryMode : std::uint8_t {
    off,
    trusted,
    open,
};

struct OnionEndpoint {
    std::string host;
    std::uint16_t port = 0;

    bool operator==(const OnionEndpoint &) const = default;
    auto operator<=>(const OnionEndpoint &) const = default;
};

struct PeerDiscoveryOptions {
    DiscoveryMode mode = DiscoveryMode::off;
    std::vector<OnionEndpoint> advertised_endpoints;
};

enum class PeerRecordKind : std::uint8_t {
    live = 1,
    tombstone = 2,
};

// Version 1 deliberately binds one signed identity to one endpoint.  Treating
// reachability as a record-wide bit would otherwise let one verified endpoint
// launder additional, unverified destinations into the routing table.
constexpr std::size_t kMaximumPeerRecordEndpoints = 1;
constexpr std::size_t kMaximumPeerRecordSize = 1'024;
constexpr std::uint64_t kPeerRecordMaximumLifetimeSeconds = 2ULL * 60ULL * 60ULL;
constexpr std::uint64_t kPeerRecordLifetimeSeconds = 60ULL * 60ULL;
constexpr std::uint64_t kPeerRecordFutureSkewSeconds = 5ULL * 60ULL;
constexpr std::uint64_t kPeerCapabilityEventGossip = 1ULL;

bool is_canonical_onion_v3(std::string_view host);
OnionEndpoint parse_advertised_peer_uri(std::string_view uri);
std::string advertised_peer_uri(const OnionEndpoint &endpoint);
Hash peer_node_id(const Hash &network, const PublicKey &identity);

struct PeerRecord {
    Hash network{};
    PublicKey identity{};
    PeerRecordKind kind = PeerRecordKind::live;
    std::uint64_t sequence = 0;
    std::uint64_t issued_at = 0;
    std::uint64_t expires_at = 0;
    std::uint64_t capabilities = 0;
    std::vector<OnionEndpoint> endpoints;
    Signature signature{};

    static PeerRecord create(const Hash &network, const crypto::Identity &identity,
                             std::uint64_t sequence, std::uint64_t issued_at,
                             std::uint64_t expires_at, std::uint64_t capabilities,
                             std::vector<OnionEndpoint> endpoints);
    static PeerRecord deserialize(std::span<const Byte> wire);

    Bytes unsigned_bytes() const;
    Bytes serialize() const;
    Hash digest() const;
    Hash id() const;
    Hash node_id() const;
    bool tombstone() const noexcept;
    bool time_window_is_valid(std::uint64_t now_seconds) const noexcept;
    void precheck(const Hash &expected_network, std::uint64_t now_seconds) const;
    void verify_signature() const;
    void validate(const Hash &expected_network, std::uint64_t now_seconds) const;
};

enum class PeerRecordInsertStatus : std::uint8_t {
    inserted,
    updated,
    duplicate,
    stale,
    equivocation,
    local_identity,
    bucket_full,
    unanchored_tombstone,
};

enum class PeerRecordPriority : std::uint8_t {
    ordinary,
    anchored_withdrawal,
    trusted,
};

struct PeerRecordAdmission {
    bool endpoint_verified = false;
    bool identity_anchored = false;
    PeerRecordPriority priority = PeerRecordPriority::ordinary;
};

class PeerDirectory {
  public:
    PeerDirectory(Hash network, PublicKey local_identity);

    std::optional<PeerRecordInsertStatus> classify(const PeerRecord &record,
                                                   std::uint64_t now_seconds);
    PeerRecordInsertStatus preview_insert(const PeerRecord &record, std::uint64_t now_seconds,
                                          PeerRecordAdmission admission = {});
    PeerRecordInsertStatus insert(const PeerRecord &record, std::uint64_t now_seconds,
                                  PeerRecordAdmission admission = {});
    PeerRecordInsertStatus insert_verified(const PeerRecord &record, std::uint64_t now_seconds,
                                           PeerRecordAdmission admission = {});
    bool mark_verified(const PublicKey &identity, std::uint64_t sequence,
                       std::uint64_t now_seconds);
    std::optional<PeerRecord> find(const PublicKey &identity, std::uint64_t now_seconds);
    std::vector<PeerRecord> closest(const Hash &target, std::size_t limit,
                                    std::uint64_t now_seconds);
    std::vector<PeerRecord> dial_candidates(const Hash &target, std::size_t limit,
                                            std::uint64_t now_seconds);
    void erase(const PublicKey &identity);
    void prune(std::uint64_t now_seconds);
    std::size_t size() const noexcept;
    const Hash &local_node_id() const noexcept;

  private:
    struct Entry {
        PeerRecord record;
        bool endpoint_verified = false;
        bool withdrawal_anchored = false;
        PeerRecordPriority priority = PeerRecordPriority::ordinary;
        std::chrono::steady_clock::time_point deadline;
    };

    struct Bucket {
        std::vector<Entry> primary;
        std::vector<Entry> replacements;
    };

    std::size_t bucket_for(const PublicKey &identity) const;
    static Entry make_entry(const PeerRecord &record, std::uint64_t now_seconds,
                            bool endpoint_verified, bool identity_anchored,
                            PeerRecordPriority priority);
    static void prune_bucket(Bucket &bucket, std::uint64_t now_seconds);

    static constexpr std::size_t kBucketCount = 256;
    static constexpr std::size_t kBucketCapacity = 8;
    Hash network_{};
    PublicKey local_identity_{};
    Hash local_node_id_{};
    std::array<Bucket, kBucketCount> buckets_;
};

bool peer_record_distance_less(const PeerRecord &left, const PeerRecord &right, const Hash &target);

} // namespace kairc
