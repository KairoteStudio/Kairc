#pragma once

#include "kairc/discovery.hpp"
#include "kairc/event.hpp"

#include <filesystem>
#include <optional>

struct sqlite3;

namespace kairc {

enum class InsertStatus : std::uint8_t {
    inserted,
    duplicate,
    missing_parent,
    quota_exceeded,
};

enum class PeerRecordStoreStatus : std::uint8_t {
    stored,
    duplicate,
    stale,
    equivocation,
    protected_downgrade,
    quota_exceeded,
};

// Open discovery can retain at most this many untrusted identity watermarks.
// A separate reserve covers all 256 configured trusted identities, the 64
// permitted local identity histories, and one retiring trusted generation.
// Retired protected rows cannot be refreshed as ordinary records and age out
// with the durable rollback watermark.
inline constexpr std::size_t kMaximumUntrustedStoredPeerRecords = 4'096;
inline constexpr std::size_t kMaximumConfiguredTrustedPeerRecords = 256;
inline constexpr std::size_t kMaximumLocalPeerRecordIdentities = 64;
inline constexpr std::size_t kRetiringTrustedPeerRecordReserve = 256;
inline constexpr std::size_t kProtectedStoredPeerRecordReserve =
    kMaximumConfiguredTrustedPeerRecords + kMaximumLocalPeerRecordIdentities +
    kRetiringTrustedPeerRecordReserve;
inline constexpr std::size_t kMaximumStoredPeerRecords =
    kMaximumUntrustedStoredPeerRecords + kProtectedStoredPeerRecordReserve;

struct EventStoreOptions {
    std::uint64_t max_bytes = 512ULL * 1024ULL * 1024ULL;
    std::size_t max_events_per_epoch = 100'000;
};

class EventStore {
  public:
    EventStore(const std::filesystem::path &path, Hash network, EventStoreOptions options = {});
    ~EventStore();

    EventStore(const EventStore &) = delete;
    EventStore &operator=(const EventStore &) = delete;

    bool contains(const Hash &id) const;
    std::optional<Event> load(const Hash &id) const;
    std::vector<Hash> missing_parents(const Event &event) const;
    InsertStatus insert(const Event &event);

    std::vector<Hash> tips(std::uint64_t epoch, std::size_t limit) const;
    std::vector<Hash> recent_ids(std::size_t limit) const;
    std::vector<Event> recent_for_channel(const Hash &channel, std::size_t limit) const;
    std::optional<std::uint64_t> canonical_layer(const Hash &id) const;
    std::vector<Bytes> load_peer_records(std::uint64_t now_seconds) const;
    PeerRecordStoreStatus store_peer_record(const PeerRecord &record,
                                            std::uint64_t observed_at_seconds,
                                            bool trusted_priority);
    bool peer_record_is_known(const PublicKey &identity) const;
    bool peer_record_has_verified_history(const PublicKey &identity) const;
    bool mark_peer_record_verified(const PublicKey &identity, std::uint64_t sequence,
                                   std::uint64_t now_seconds);
    std::uint64_t next_peer_record_sequence(const PublicKey &identity, std::uint64_t floor);
    void prune_peer_records(std::uint64_t now_seconds);
    void prune_before_epoch(std::uint64_t first_epoch_to_keep);
    std::size_t size() const;
    std::uint64_t storage_bytes() const;
    void checkpoint(bool truncate);

  private:
    sqlite3 *database_ = nullptr;
    Hash network_{};
    std::filesystem::path path_;
    EventStoreOptions options_;
};

} // namespace kairc
