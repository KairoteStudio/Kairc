#include "kairc/node.hpp"

#include <algorithm>
#include <limits>

namespace kairc {

namespace {

constexpr std::size_t kMaximumLocalChannels = 1024;

NodeOptions validate_options(NodeOptions options) {
    if (options.network_id.empty() || options.network_id.size() > 128) {
        throw Error("network_id must contain between 1 and 128 bytes");
    }
    if (options.work_bits > 24) {
        throw Error("work_bits must be between 0 and 24");
    }
    if (options.retention_hours == 0 || options.retention_hours > 24ULL * 365ULL) {
        throw Error("retention_hours must be between 1 and 8760");
    }
    if (options.pending_limit == 0 || options.pending_limit > 65536) {
        throw Error("pending_limit must be between 1 and 65536");
    }
    constexpr std::uint64_t minimum_store_bytes = 16ULL * 1024ULL * 1024ULL;
    constexpr std::uint64_t maximum_store_bytes = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    if (options.max_store_bytes < minimum_store_bytes ||
        options.max_store_bytes > maximum_store_bytes) {
        throw Error("max_store_bytes must be between 16 MiB and 1 TiB");
    }
    if (options.max_events_per_epoch == 0 || options.max_events_per_epoch > 10'000'000) {
        throw Error("max_events_per_epoch must be between 1 and 10000000");
    }
    if (options.verification_workers == 0 || options.verification_workers > 256) {
        throw Error("verification_workers must be between 1 and 256");
    }
    if (options.presentation_delay_ms > 5'000) {
        throw Error("presentation_delay_ms must be between 0 and 5000");
    }
    if (options.pending_per_peer_limit == 0 ||
        options.pending_per_peer_limit > options.pending_limit) {
        throw Error("pending_per_peer_limit must be between 1 and pending_limit");
    }
    if (options.pending_ttl_seconds < 30 || options.pending_ttl_seconds > 3'600) {
        throw Error("pending_ttl_seconds must be between 30 and 3600");
    }
    return options;
}

class VerificationPermit {
  public:
    VerificationPermit(std::counting_semaphore<65'536> &slots, bool wait) : slots_(slots) {
        acquired_ = wait ? (slots_.acquire(), true) : slots_.try_acquire();
    }

    ~VerificationPermit() {
        if (acquired_) {
            slots_.release();
        }
    }

    bool acquired() const noexcept {
        return acquired_;
    }

  private:
    std::counting_semaphore<65'536> &slots_;
    bool acquired_ = false;
};

} // namespace

Node::Node(const std::filesystem::path &database_path, NodeOptions options)
    : options_(validate_options(std::move(options))),
      network_(network_hash(options_.network_id, options_.work_bits)),
      store_(database_path, network_,
             EventStoreOptions{options_.max_store_bytes, options_.max_events_per_epoch}),
      verification_slots_(static_cast<std::ptrdiff_t>(options_.verification_workers)) {
    const std::uint64_t current_epoch = unix_time_ms() / kEpochMilliseconds;
    store_.prune_before_epoch(first_retained_epoch(current_epoch));
    last_pruned_epoch_ = current_epoch;
}

void Node::register_public_channel(std::string_view name) {
    const std::string canonical = canonical_channel(name);
    std::lock_guard lock(mutex_);
    if (channels_by_name_.contains(canonical)) {
        return;
    }
    if (channels_by_name_.size() >= kMaximumLocalChannels) {
        throw Error("local channel registry limit reached");
    }
    Channel channel = Channel::public_channel(canonical, network_);
    if (names_by_tag_.contains(channel.tag())) {
        throw Error("channel tag is already assigned to another local channel");
    }
    names_by_tag_[channel.tag()] = canonical;
    channels_by_name_.emplace(canonical, std::move(channel));
}

void Node::register_private_channel(std::string_view name, std::span<const Byte> secret) {
    const std::string canonical = canonical_channel(name);
    Channel channel = Channel::private_channel(canonical, network_, secret);
    std::lock_guard lock(mutex_);
    if (channels_by_name_.contains(canonical)) {
        throw Error("channel is configured more than once: " + canonical);
    }
    if (channels_by_name_.size() >= kMaximumLocalChannels) {
        throw Error("local channel registry limit reached");
    }
    if (names_by_tag_.contains(channel.tag())) {
        throw Error("a private channel secret is reused by another local channel");
    }
    names_by_tag_[channel.tag()] = canonical;
    channels_by_name_.emplace(canonical, std::move(channel));
}

bool Node::channel_is_encrypted(std::string_view name) const {
    const std::string canonical = canonical_channel(name);
    std::lock_guard lock(mutex_);
    const auto found = channels_by_name_.find(canonical);
    return found != channels_by_name_.end() && found->second.encrypted();
}

Channel &Node::ensure_public_channel_locked(std::string_view name) {
    const std::string canonical = canonical_channel(name);
    if (auto found = channels_by_name_.find(canonical); found != channels_by_name_.end()) {
        return found->second;
    }
    if (channels_by_name_.size() >= kMaximumLocalChannels) {
        throw Error("local channel registry limit reached");
    }
    Channel channel = Channel::public_channel(canonical, network_);
    if (names_by_tag_.contains(channel.tag())) {
        throw Error("channel tag is already assigned to another local channel");
    }
    names_by_tag_[channel.tag()] = canonical;
    return channels_by_name_.emplace(canonical, std::move(channel)).first->second;
}

Event Node::publish(std::string_view channel_name, std::string nickname, std::string text,
                    bool notify_local) {
    Channel channel;
    std::vector<Hash> parents;
    const std::uint64_t timestamp = unix_time_ms();
    const std::uint64_t epoch = timestamp / kEpochMilliseconds;
    {
        std::lock_guard lock(mutex_);
        channel = ensure_public_channel_locked(channel_name);
        parents = store_.tips(epoch, kMaxEventParents);
    }
    if (parents.empty()) {
        parents.push_back(epoch_root(network_, epoch));
    }

    crypto::Identity identity = crypto::Identity::generate();
    Event event;
    event.network = network_;
    event.timestamp_ms = timestamp;
    event.author = identity.public_key;
    event.parents = std::move(parents);
    event.channel = channel.tag();
    const Bytes event_context = event.payload_context();
    const auto [nonce, content] =
        channel.encode(ChatMessage{std::move(nickname), std::move(text)}, event_context);
    event.content_nonce = nonce;
    event.content = content;
    // A fresh signing key for every event prevents the wire-level author key
    // from becoming a durable node or account identifier. Nicknames remain
    // intentionally unverified pseudonyms inside the encrypted/plain payload.
    event.seal(identity, options_.work_bits);

    IngestResult result = ingest(event, notify_local);
    if (result.status != IngestStatus::accepted) {
        throw Error("locally created event was rejected: " + result.error);
    }
    return event;
}

IngestResult Node::ingest(Event event, bool notify_local) {
    return ingest_impl(std::move(event), notify_local, false, std::nullopt);
}

IngestResult Node::ingest_peer(Event event, const PublicKey &peer_identity, bool notify_local) {
    return ingest_impl(std::move(event), notify_local, true, peer_identity);
}

IngestResult Node::ingest_impl(Event event, bool notify_local, bool remote,
                               std::optional<PublicKey> source) {
    IngestResult result;
    try {
        const Hash calculated_id = event.calculate_id();
        if (event.id != Hash{} && event.id != calculated_id) {
            result.error = "event ID does not match its content";
            return result;
        }
        event.id = calculated_id;
    } catch (const Error &exception) {
        result.error = exception.what();
        return result;
    }

    // A repeated event is rejected before consuming an Ed25519 verification slot.
    // The ID was recomputed above, so an untrusted caller cannot select an arbitrary
    // existing row and use this fast path to bypass content validation.
    {
        std::lock_guard lock(mutex_);
        if (store_.contains(event.id)) {
            result.status = IngestStatus::duplicate;
            return result;
        }
        if (pending_.contains(event.id)) {
            result.status = IngestStatus::pending_parents;
            const auto &missing = pending_.at(event.id).missing;
            result.missing.assign(missing.begin(), missing.end());
            std::sort(result.missing.begin(), result.missing.end());
            return result;
        }
    }

    VerificationPermit permit(verification_slots_, !remote);
    if (!permit.acquired()) {
        result.error = "cryptographic verification capacity is saturated";
        return result;
    }
    if (!event.verify(network_, options_.work_bits, unix_time_ms(), &result.error)) {
        return result;
    }

    std::vector<DeliveredMessage> delivered;
    std::function<void(const DeliveredMessage &)> handler;
    {
        std::lock_guard lock(mutex_);
        const auto collect_delivery = [&](const Event &accepted, bool accepted_remote,
                                          bool accepted_notify_local) {
            if (!accepted_notify_local) {
                return;
            }
            auto message = decode_locked(accepted);
            if (!message) {
                return;
            }
            if (accepted_remote && options_.presentation_delay_ms != 0 &&
                presentation_queue_.size() < options_.pending_limit) {
                const auto layer = store_.canonical_layer(accepted.id);
                if (!layer) {
                    throw Error("accepted event has no canonical layer");
                }
                presentation_queue_.push_back(QueuedDelivery{
                    .message = std::move(*message),
                    .epoch = accepted.epoch(),
                    .layer = *layer,
                    .ready_at = std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(options_.presentation_delay_ms),
                });
                return;
            }
            delivered.push_back(std::move(*message));
        };
        const std::uint64_t current_epoch = unix_time_ms() / kEpochMilliseconds;
        prune_locked(current_epoch);
        if (event.epoch() < first_retained_epoch(current_epoch)) {
            result.error = "event is older than this node's retention window";
            return result;
        }
        if (store_.contains(event.id)) {
            result.status = IngestStatus::duplicate;
            return result;
        }

        try {
            result.missing = store_.missing_parents(event);
        } catch (const Error &exception) {
            result.error = exception.what();
            return result;
        }
        if (!result.missing.empty()) {
            if (!pending_.contains(event.id)) {
                if (pending_.size() >= options_.pending_limit) {
                    result.error = "pending-event limit reached";
                    return result;
                }
                if (source && pending_by_peer_[*source] >= options_.pending_per_peer_limit) {
                    result.error = "peer pending-event limit reached";
                    return result;
                }
                PendingEvent pending{
                    .event = std::move(event),
                    .missing = {result.missing.begin(), result.missing.end()},
                    .source = source,
                    .remote = remote,
                    .notify_local = notify_local,
                    .expires_at = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(options_.pending_ttl_seconds),
                };
                const Hash pending_id = pending.event.id;
                for (const Hash &parent : pending.missing) {
                    pending_by_parent_[parent].insert(pending_id);
                }
                if (source) {
                    ++pending_by_peer_[*source];
                }
                pending_.emplace(pending_id, std::move(pending));
            }
            result.status = IngestStatus::pending_parents;
            return result;
        }

        const InsertStatus inserted = store_.insert(event);
        if (inserted == InsertStatus::quota_exceeded) {
            result.error = "event store quota reached";
            return result;
        }
        if (inserted != InsertStatus::inserted) {
            result.status = IngestStatus::duplicate;
            return result;
        }
        result.accepted.push_back(event);
        collect_delivery(event, remote, notify_local);

        // Only revisit events that named a newly accepted parent. This makes
        // closure processing proportional to the affected dependency edges,
        // rather than rescanning the entire pending map after every insert.
        std::vector<std::pair<Hash, std::uint64_t>> available{{event.id, event.epoch()}};
        for (std::size_t cursor = 0; cursor < available.size(); ++cursor) {
            const auto [parent, parent_epoch] = available[cursor];
            const auto waiting_iterator = pending_by_parent_.find(parent);
            if (waiting_iterator == pending_by_parent_.end()) {
                continue;
            }
            std::vector<Hash> children(waiting_iterator->second.begin(),
                                       waiting_iterator->second.end());
            pending_by_parent_.erase(waiting_iterator);
            for (const Hash &child : children) {
                const auto pending_iterator = pending_.find(child);
                if (pending_iterator == pending_.end()) {
                    continue;
                }
                PendingEvent &pending = pending_iterator->second;
                if (pending.event.epoch() != parent_epoch) {
                    // A missing parent could not be epoch-checked when the child
                    // first arrived. Drop only that invalid child and keep
                    // processing every other dependent of this parent.
                    erase_pending_locked(child);
                    continue;
                }
                pending.missing.erase(parent);
                if (!pending.missing.empty()) {
                    continue;
                }
                PendingEvent ready = std::move(pending);
                if (ready.source) {
                    auto count = pending_by_peer_.find(*ready.source);
                    if (count != pending_by_peer_.end() && --count->second == 0) {
                        pending_by_peer_.erase(count);
                    }
                }
                pending_.erase(pending_iterator);
                const InsertStatus ready_status = store_.insert(ready.event);
                if (ready_status != InsertStatus::inserted) {
                    continue;
                }
                available.emplace_back(ready.event.id, ready.event.epoch());
                result.accepted.push_back(ready.event);
                collect_delivery(ready.event, ready.remote, ready.notify_local);
            }
        }
        result.status = IngestStatus::accepted;
        if (!delivered.empty()) {
            handler = message_handler_;
        }
    }

    if (handler) {
        for (const DeliveredMessage &message : delivered) {
            handler(message);
        }
    }
    return result;
}

std::vector<Hash> Node::recent_ids(std::size_t limit) const {
    std::lock_guard lock(mutex_);
    return store_.recent_ids(limit);
}

std::optional<Event> Node::load(const Hash &id) const {
    std::lock_guard lock(mutex_);
    return store_.load(id);
}

std::vector<DeliveredMessage> Node::history(std::string_view channel_name,
                                            std::size_t limit) const {
    const std::string canonical = canonical_channel(channel_name);
    std::lock_guard lock(mutex_);
    const auto found = channels_by_name_.find(canonical);
    if (found == channels_by_name_.end()) {
        return {};
    }
    std::vector<DeliveredMessage> output;
    for (const Event &event : store_.recent_for_channel(found->second.tag(), limit)) {
        if (auto message = decode_locked(event)) {
            message->replayed = true;
            output.push_back(std::move(*message));
        }
    }
    return output;
}

std::vector<Bytes> Node::load_peer_records(std::uint64_t now_seconds) const {
    std::lock_guard lock(mutex_);
    return store_.load_peer_records(now_seconds);
}

PeerRecordStoreStatus Node::store_peer_record(const PeerRecord &record,
                                              std::uint64_t observed_at_seconds,
                                              bool trusted_priority) {
    std::lock_guard lock(mutex_);
    return store_.store_peer_record(record, observed_at_seconds, trusted_priority);
}

bool Node::peer_record_is_known(const PublicKey &identity) const {
    std::lock_guard lock(mutex_);
    return store_.peer_record_is_known(identity);
}

bool Node::peer_record_has_verified_history(const PublicKey &identity) const {
    std::lock_guard lock(mutex_);
    return store_.peer_record_has_verified_history(identity);
}

bool Node::mark_peer_record_verified(const PublicKey &identity, std::uint64_t sequence,
                                     std::uint64_t now_seconds) {
    std::lock_guard lock(mutex_);
    return store_.mark_peer_record_verified(identity, sequence, now_seconds);
}

std::uint64_t Node::next_peer_record_sequence(const PublicKey &identity, std::uint64_t floor) {
    std::lock_guard lock(mutex_);
    return store_.next_peer_record_sequence(identity, floor);
}

void Node::prune_peer_records(std::uint64_t now_seconds) {
    std::lock_guard lock(mutex_);
    store_.prune_peer_records(now_seconds);
}

void Node::set_message_handler(std::function<void(const DeliveredMessage &)> handler) {
    std::lock_guard lock(mutex_);
    message_handler_ = std::move(handler);
}

void Node::maintain() {
    std::vector<QueuedDelivery> ready;
    std::function<void(const DeliveredMessage &)> handler;
    {
        std::lock_guard lock(mutex_);
        prune_locked(unix_time_ms() / kEpochMilliseconds);
        const auto now = std::chrono::steady_clock::now();
        for (auto iterator = presentation_queue_.begin(); iterator != presentation_queue_.end();) {
            if (iterator->ready_at <= now) {
                ready.push_back(std::move(*iterator));
                iterator = presentation_queue_.erase(iterator);
            } else {
                ++iterator;
            }
        }
        handler = message_handler_;
    }
    std::sort(ready.begin(), ready.end(),
              [](const QueuedDelivery &left, const QueuedDelivery &right) {
                  if (left.epoch != right.epoch) {
                      return left.epoch < right.epoch;
                  }
                  if (left.layer != right.layer) {
                      return left.layer < right.layer;
                  }
                  return left.message.event_id < right.message.event_id;
              });
    if (handler) {
        for (const QueuedDelivery &delivery : ready) {
            handler(delivery.message);
        }
    }
}

std::uint64_t Node::first_retained_epoch(std::uint64_t current_epoch) const {
    const std::uint64_t preceding = options_.retention_hours - 1;
    return current_epoch > preceding ? current_epoch - preceding : 0;
}

void Node::prune_locked(std::uint64_t current_epoch) {
    const std::uint64_t first_epoch = first_retained_epoch(current_epoch);
    prune_pending_locked(first_epoch, std::chrono::steady_clock::now());
    if (current_epoch > last_pruned_epoch_) {
        store_.prune_before_epoch(first_epoch);
        last_pruned_epoch_ = current_epoch;
    }
}

void Node::erase_pending_locked(const Hash &id) {
    const auto iterator = pending_.find(id);
    if (iterator == pending_.end()) {
        return;
    }
    for (const Hash &parent : iterator->second.missing) {
        auto dependents = pending_by_parent_.find(parent);
        if (dependents == pending_by_parent_.end()) {
            continue;
        }
        dependents->second.erase(id);
        if (dependents->second.empty()) {
            pending_by_parent_.erase(dependents);
        }
    }
    if (iterator->second.source) {
        auto count = pending_by_peer_.find(*iterator->second.source);
        if (count != pending_by_peer_.end() && --count->second == 0) {
            pending_by_peer_.erase(count);
        }
    }
    pending_.erase(iterator);
}

void Node::prune_pending_locked(std::uint64_t first_epoch,
                                std::chrono::steady_clock::time_point now) {
    std::vector<Hash> expired;
    expired.reserve(pending_.size());
    for (const auto &[id, pending] : pending_) {
        if (pending.event.epoch() < first_epoch || pending.expires_at <= now) {
            expired.push_back(id);
        }
    }
    for (const Hash &id : expired) {
        erase_pending_locked(id);
    }
}

std::optional<DeliveredMessage> Node::decode_locked(const Event &event) const {
    const auto name = names_by_tag_.find(event.channel);
    if (name == names_by_tag_.end()) {
        return std::nullopt;
    }
    const auto channel = channels_by_name_.find(name->second);
    if (channel == channels_by_name_.end()) {
        return std::nullopt;
    }
    const Bytes event_context = event.payload_context();
    const auto chat = channel->second.decode(event.content_nonce, event.content, event_context);
    if (!chat) {
        return std::nullopt;
    }
    const std::uint64_t now = unix_time_ms();
    const std::uint64_t replay_threshold = options_.presentation_delay_ms + 1'000;
    const bool replayed = event.timestamp_ms < now && now - event.timestamp_ms > replay_threshold;
    return DeliveredMessage{
        .event_id = event.id,
        .timestamp_ms = event.timestamp_ms,
        .channel = channel->second.name(),
        .nickname = chat->nickname,
        .text = chat->text,
        .encrypted = channel->second.encrypted(),
        .replayed = replayed,
    };
}

} // namespace kairc
