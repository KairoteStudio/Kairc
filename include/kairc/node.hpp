#pragma once

#include "kairc/channel.hpp"
#include "kairc/event_store.hpp"

#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <semaphore>
#include <unordered_map>
#include <unordered_set>

namespace kairc {

struct NodeOptions {
    std::string network_id = "kairc-devnet-1";
    std::uint8_t work_bits = 12;
    std::uint64_t retention_hours = 24;
    std::size_t pending_limit = 2048;
    std::uint64_t max_store_bytes = 512ULL * 1024ULL * 1024ULL;
    std::size_t max_events_per_epoch = 100'000;
    std::size_t verification_workers = 4;
    std::uint64_t presentation_delay_ms = 750;
    std::size_t pending_per_peer_limit = 256;
    std::uint64_t pending_ttl_seconds = 300;
};

struct DeliveredMessage {
    Hash event_id{};
    std::uint64_t timestamp_ms = 0;
    std::string channel;
    std::string nickname;
    std::string text;
    bool encrypted = false;
    bool replayed = false;
};

enum class IngestStatus : std::uint8_t {
    accepted,
    duplicate,
    pending_parents,
    rejected,
};

struct IngestResult {
    IngestStatus status = IngestStatus::rejected;
    std::vector<Event> accepted;
    std::vector<Hash> missing;
    std::string error;
};

class Node {
  public:
    Node(const std::filesystem::path &database_path, NodeOptions options);

    const Hash &network() const noexcept {
        return network_;
    }
    std::uint8_t work_bits() const noexcept {
        return options_.work_bits;
    }

    void register_public_channel(std::string_view name);
    void register_private_channel(std::string_view name, std::span<const Byte> secret);
    bool channel_is_encrypted(std::string_view name) const;

    Event publish(std::string_view channel, std::string nickname, std::string text,
                  bool notify_local = true);
    IngestResult ingest(Event event, bool notify_local = true);
    IngestResult ingest_peer(Event event, const PublicKey &peer_identity, bool notify_local = true);

    std::vector<Hash> recent_ids(std::size_t limit) const;
    std::optional<Event> load(const Hash &id) const;
    std::vector<DeliveredMessage> history(std::string_view channel, std::size_t limit) const;

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

    void set_message_handler(std::function<void(const DeliveredMessage &)> handler);
    void maintain();

  private:
    struct QueuedDelivery {
        DeliveredMessage message;
        std::uint64_t epoch = 0;
        std::uint64_t layer = 0;
        std::chrono::steady_clock::time_point ready_at;
    };

    struct PendingEvent {
        Event event;
        std::unordered_set<Hash, HashHasher> missing;
        std::optional<PublicKey> source;
        bool remote = false;
        bool notify_local = true;
        std::chrono::steady_clock::time_point expires_at;
    };

    std::uint64_t first_retained_epoch(std::uint64_t current_epoch) const;
    void prune_locked(std::uint64_t current_epoch);
    IngestResult ingest_impl(Event event, bool notify_local, bool remote,
                             std::optional<PublicKey> source = std::nullopt);
    void erase_pending_locked(const Hash &id);
    void prune_pending_locked(std::uint64_t first_epoch, std::chrono::steady_clock::time_point now);
    std::optional<DeliveredMessage> decode_locked(const Event &event) const;
    Channel &ensure_public_channel_locked(std::string_view name);

    NodeOptions options_;
    Hash network_{};
    mutable std::mutex mutex_;
    EventStore store_;
    std::counting_semaphore<65'536> verification_slots_;
    std::unordered_map<std::string, Channel> channels_by_name_;
    std::unordered_map<Hash, std::string, HashHasher> names_by_tag_;
    std::unordered_map<Hash, PendingEvent, HashHasher> pending_;
    std::unordered_map<Hash, std::unordered_set<Hash, HashHasher>, HashHasher> pending_by_parent_;
    std::unordered_map<PublicKey, std::size_t, HashHasher> pending_by_peer_;
    std::vector<QueuedDelivery> presentation_queue_;
    std::function<void(const DeliveredMessage &)> message_handler_;
    std::uint64_t last_pruned_epoch_ = 0;
};

} // namespace kairc
