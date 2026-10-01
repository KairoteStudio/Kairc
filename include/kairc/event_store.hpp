#pragma once

#include "kairc/event.hpp"

#include <filesystem>
#include <optional>

struct sqlite3;

namespace kairc {

enum class InsertStatus : std::uint8_t {
    inserted,
    duplicate,
    missing_parent,
};

class EventStore {
  public:
    EventStore(const std::filesystem::path &path, Hash network);
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
    void prune_before_epoch(std::uint64_t first_epoch_to_keep);
    std::size_t size() const;

  private:
    sqlite3 *database_ = nullptr;
    Hash network_{};
};

} // namespace kairc
