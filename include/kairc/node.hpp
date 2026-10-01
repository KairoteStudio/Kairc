#pragma once

#include "kairc/channel.hpp"
#include "kairc/event_store.hpp"

#include <functional>
#include <mutex>
#include <unordered_map>

namespace kairc {

struct NodeOptions {
    std::string network_id = "kairc-devnet-1";
    std::uint8_t work_bits = 12;
    std::uint64_t retention_hours = 24;
    std::size_t pending_limit = 2048;
};

struct DeliveredMessage {
    Hash event_id{};
    std::uint64_t timestamp_ms = 0;
    std::string channel;
    std::string nickname;
    std::string text;
    bool encrypted = false;
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

    std::vector<Hash> recent_ids(std::size_t limit) const;
    std::optional<Event> load(const Hash &id) const;
    std::vector<DeliveredMessage> history(std::string_view channel, std::size_t limit) const;

    void set_message_handler(std::function<void(const DeliveredMessage &)> handler);
    void maintain();

  private:
    std::uint64_t first_retained_epoch(std::uint64_t current_epoch) const;
    void prune_locked(std::uint64_t current_epoch);
    std::optional<DeliveredMessage> decode_locked(const Event &event) const;
    Channel &ensure_public_channel_locked(std::string_view name);

    NodeOptions options_;
    Hash network_{};
    mutable std::mutex mutex_;
    EventStore store_;
    std::unordered_map<std::string, Channel> channels_by_name_;
    std::unordered_map<Hash, std::string, HashHasher> names_by_tag_;
    std::unordered_map<Hash, Event, HashHasher> pending_;
    std::function<void(const DeliveredMessage &)> message_handler_;
    std::uint64_t last_pruned_epoch_ = 0;
};

} // namespace kairc
