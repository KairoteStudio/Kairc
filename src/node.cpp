#include "kairc/node.hpp"

#include <algorithm>

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
    return options;
}

} // namespace

Node::Node(const std::filesystem::path &database_path, NodeOptions options)
    : options_(validate_options(std::move(options))),
      network_(network_hash(options_.network_id, options_.work_bits)),
      store_(database_path, network_) {
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
    IngestResult result;
    if (event.id == Hash{}) {
        try {
            event.id = event.calculate_id();
        } catch (const Error &exception) {
            result.error = exception.what();
            return result;
        }
    }
    if (!event.verify(network_, options_.work_bits, unix_time_ms(), &result.error)) {
        return result;
    }

    std::vector<DeliveredMessage> delivered;
    std::function<void(const DeliveredMessage &)> handler;
    {
        std::lock_guard lock(mutex_);
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
                pending_.emplace(event.id, std::move(event));
            }
            result.status = IngestStatus::pending_parents;
            return result;
        }

        if (store_.insert(event) != InsertStatus::inserted) {
            result.status = IngestStatus::duplicate;
            return result;
        }
        result.accepted.push_back(event);
        if (auto message = decode_locked(event)) {
            delivered.push_back(std::move(*message));
        }

        bool progress = true;
        while (progress) {
            progress = false;
            for (auto iterator = pending_.begin(); iterator != pending_.end();) {
                std::vector<Hash> missing;
                try {
                    missing = store_.missing_parents(iterator->second);
                } catch (const Error &) {
                    iterator = pending_.erase(iterator);
                    continue;
                }
                if (!missing.empty()) {
                    ++iterator;
                    continue;
                }
                Event ready = std::move(iterator->second);
                iterator = pending_.erase(iterator);
                if (store_.insert(ready) == InsertStatus::inserted) {
                    result.accepted.push_back(ready);
                    if (auto message = decode_locked(ready)) {
                        delivered.push_back(std::move(*message));
                    }
                    progress = true;
                }
            }
        }
        result.status = IngestStatus::accepted;
        if (notify_local) {
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
            output.push_back(std::move(*message));
        }
    }
    return output;
}

void Node::set_message_handler(std::function<void(const DeliveredMessage &)> handler) {
    std::lock_guard lock(mutex_);
    message_handler_ = std::move(handler);
}

void Node::maintain() {
    std::lock_guard lock(mutex_);
    prune_locked(unix_time_ms() / kEpochMilliseconds);
}

std::uint64_t Node::first_retained_epoch(std::uint64_t current_epoch) const {
    const std::uint64_t preceding = options_.retention_hours - 1;
    return current_epoch > preceding ? current_epoch - preceding : 0;
}

void Node::prune_locked(std::uint64_t current_epoch) {
    if (current_epoch <= last_pruned_epoch_) {
        return;
    }
    const std::uint64_t first_epoch = first_retained_epoch(current_epoch);
    store_.prune_before_epoch(first_epoch);
    for (auto iterator = pending_.begin(); iterator != pending_.end();) {
        if (iterator->second.epoch() < first_epoch) {
            iterator = pending_.erase(iterator);
        } else {
            ++iterator;
        }
    }
    last_pruned_epoch_ = current_epoch;
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
    return DeliveredMessage{
        .event_id = event.id,
        .timestamp_ms = event.timestamp_ms,
        .channel = channel->second.name(),
        .nickname = chat->nickname,
        .text = chat->text,
        .encrypted = channel->second.encrypted(),
    };
}

} // namespace kairc
