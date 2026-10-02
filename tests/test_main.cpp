#include "kairc/channel.hpp"
#include "kairc/config.hpp"
#include "kairc/discovery.hpp"
#include "kairc/event.hpp"
#include "kairc/event_store.hpp"
#include "kairc/irc.hpp"
#include "kairc/node.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace {

int failures = 0;

void check(bool condition, std::string_view message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

std::filesystem::path temporary_database(std::string_view name) {
    const auto random = kairc::hex(kairc::crypto::random_bytes(8));
    return std::filesystem::temp_directory_path() /
           ("kairc-test-" + std::string(name) + "-" + random + ".db");
}

kairc::Event make_event(const kairc::Hash &network, const std::vector<kairc::Hash> &parents,
                        const kairc::Hash &channel, std::string nickname, std::string text,
                        std::uint8_t work_bits = 4, std::uint64_t timestamp_ms = 0) {
    const kairc::Channel room = kairc::Channel::public_channel("#test", network);
    kairc::crypto::Identity identity = kairc::crypto::Identity::generate();
    kairc::Event event;
    event.network = network;
    event.timestamp_ms = timestamp_ms == 0 ? kairc::unix_time_ms() : timestamp_ms;
    event.author = identity.public_key;
    event.parents = parents;
    event.channel = channel;
    const kairc::Bytes context = event.payload_context();
    const auto [nonce, content] = room.encode({std::move(nickname), std::move(text)}, context);
    event.content_nonce = nonce;
    event.content = content;
    event.seal(identity, work_bits);
    return event;
}

std::string test_onion(char value) {
    return std::string(56, value) + ".onion";
}

kairc::PeerRecord make_stored_peer_record(const kairc::Hash &network, std::uint64_t identity_number,
                                          std::uint64_t sequence, std::uint64_t now) {
    kairc::PeerRecord record;
    record.network = network;
    record.identity.fill(0);
    record.identity.front() = 0xa5;
    for (std::size_t index = 0; index < sizeof(identity_number); ++index) {
        record.identity[index + 1] =
            static_cast<kairc::Byte>((identity_number >> (index * 8U)) & 0xffU);
    }
    record.kind = kairc::PeerRecordKind::live;
    record.sequence = sequence;
    record.issued_at = now;
    record.expires_at = now + 1;
    record.capabilities = kairc::kPeerCapabilityEventGossip;
    record.endpoints = {{test_onion('c'), 7780}};
    return record;
}

void test_channel_crypto() {
    const auto network = kairc::network_hash("testnet", 4);
    const kairc::Bytes secret = kairc::crypto::random_bytes(32);
    const auto channel = kairc::Channel::private_channel("#Secret", network, secret);
    const kairc::Bytes context = kairc::crypto::random_bytes(32);
    const auto [nonce, ciphertext] = channel.encode({"anon", "hidden message"}, context);
    check(ciphertext != kairc::ChatMessage{"anon", "hidden message"}.serialize(),
          "private channel ciphertext differs from plaintext");
    const auto decoded = channel.decode(nonce, ciphertext, context);
    check(decoded && decoded->nickname == "anon" && decoded->text == "hidden message",
          "private channel decrypts with the shared secret");
    const auto wrong =
        kairc::Channel::private_channel("#Secret", network, kairc::crypto::random_bytes(32));
    check(!wrong.decode(nonce, ciphertext, context), "wrong channel secret cannot decrypt");
    kairc::Bytes changed_context = context;
    changed_context.front() ^= 1;
    check(!channel.decode(nonce, ciphertext, changed_context),
          "private ciphertext cannot be replayed under another event context");

    bool rejected_nickname = false;
    try {
        static_cast<void>(kairc::ChatMessage{"bad nick", "hello"}.serialize());
    } catch (const kairc::Error &) {
        rejected_nickname = true;
    }
    check(rejected_nickname, "network payload rejects IRC-unsafe nicknames");

    bool rejected_control = false;
    try {
        static_cast<void>(kairc::ChatMessage{"anon", "\x01"
                                                     "DCC SEND"}
                              .serialize());
    } catch (const kairc::Error &) {
        rejected_control = true;
    }
    check(rejected_control, "network payload rejects client control sequences");
}

void test_signed_event() {
    const auto network = kairc::network_hash("testnet", 4);
    const auto channel = kairc::Channel::public_channel("#test", network);
    const auto epoch = kairc::unix_time_ms() / kairc::kEpochMilliseconds;
    kairc::Event event =
        make_event(network, {kairc::epoch_root(network, epoch)}, channel.tag(), "alice", "hello");
    std::string error;
    check(event.verify(network, 4, kairc::unix_time_ms(), &error),
          "fresh signed event verifies: " + error);
    const auto wire = event.serialize();
    const auto decoded = kairc::Event::deserialize(wire);
    check(decoded.id == event.id, "event serialization preserves its content ID");
    kairc::Event alternate_signature = event;
    alternate_signature.signature.front() ^= 1;
    check(alternate_signature.calculate_id() == event.id,
          "event identity cannot be multiplied by changing its signature");
    check(!alternate_signature.verify(network, 4, kairc::unix_time_ms(), nullptr),
          "event signatures remain mandatory even though they are not identity bytes");
    event.content[0] ^= 1;
    check(!event.verify(network, 4, kairc::unix_time_ms(), nullptr), "tampered event is rejected");
}

void test_peer_discovery_records() {
    const kairc::Hash network = kairc::network_hash("discovery-testnet", 4);
    kairc::crypto::Identity local = kairc::crypto::Identity::generate();
    kairc::crypto::Identity remote = kairc::crypto::Identity::generate();
    const std::uint64_t now = kairc::unix_time_ms() / 1'000ULL;
    const kairc::OnionEndpoint first{test_onion('a'), 7777};
    const kairc::OnionEndpoint second{test_onion('b'), 7778};
    const kairc::PeerRecord record =
        kairc::PeerRecord::create(network, remote, 10, now, now + kairc::kPeerRecordLifetimeSeconds,
                                  kairc::kPeerCapabilityEventGossip, {first, first});
    record.validate(network, now);
    check(record.endpoints.size() == 1 && record.endpoints.front() == first,
          "peer record creation canonicalizes its single onion endpoint");
    bool rejected_multiple_endpoints = false;
    try {
        static_cast<void>(kairc::PeerRecord::create(
            network, remote, 11, now, now + kairc::kPeerRecordLifetimeSeconds,
            kairc::kPeerCapabilityEventGossip, {first, second}));
    } catch (const kairc::Error &) {
        rejected_multiple_endpoints = true;
    }
    check(rejected_multiple_endpoints,
          "peer record v1 rejects destinations that were not individually verified");
    const kairc::PeerRecord decoded = kairc::PeerRecord::deserialize(record.serialize());
    decoded.validate(network, now);
    check(decoded.id() == record.id() && decoded.node_id() == record.node_id(),
          "signed peer record round-trips with stable IDs");

    kairc::Bytes tampered_wire = record.serialize();
    tampered_wire.back() ^= 1;
    bool rejected_tamper = false;
    try {
        kairc::PeerRecord::deserialize(tampered_wire).validate(network, now);
    } catch (const kairc::Error &) {
        rejected_tamper = true;
    }
    check(rejected_tamper, "peer record rejects a modified signature");

    bool rejected_network = false;
    try {
        record.validate(kairc::network_hash("other-discovery-network", 4), now);
    } catch (const kairc::Error &) {
        rejected_network = true;
    }
    check(rejected_network, "peer record signature cannot cross network routing tables");

    kairc::PeerDirectory directory(network, local.public_key);
    check(directory.insert(record, now) == kairc::PeerRecordInsertStatus::inserted &&
              directory.closest(directory.local_node_id(), 8, now).empty() &&
              directory.dial_candidates(directory.local_node_id(), 8, now).size() == 1,
          "unverified discovery records stay in the bounded replacement cache");
    check(directory.mark_verified(record.identity, record.sequence, now) &&
              directory.closest(directory.local_node_id(), 8, now).size() == 1,
          "an exact-identity endpoint handshake promotes a discovery record");

    const kairc::PeerRecord stale =
        kairc::PeerRecord::create(network, remote, 9, now, now + kairc::kPeerRecordLifetimeSeconds,
                                  kairc::kPeerCapabilityEventGossip, {first});
    check(directory.insert(stale, now) == kairc::PeerRecordInsertStatus::stale,
          "routing table rejects a lower peer-record sequence");
    const kairc::PeerRecord equivocation =
        kairc::PeerRecord::create(network, remote, 10, now, now + kairc::kPeerRecordLifetimeSeconds,
                                  kairc::kPeerCapabilityEventGossip, {second});
    check(directory.insert(equivocation, now) == kairc::PeerRecordInsertStatus::equivocation,
          "routing table rejects conflicting bytes at one sequence");
    const kairc::PeerRecord tombstone = kairc::PeerRecord::create(
        network, remote, 11, now, now + kairc::kPeerRecordMaximumLifetimeSeconds, 0, {});
    check(directory.insert(tombstone, now) == kairc::PeerRecordInsertStatus::updated &&
              !directory.find(remote.public_key, now).has_value(),
          "a higher signed tombstone withdraws an old endpoint");
    kairc::crypto::Identity unknown = kairc::crypto::Identity::generate();
    const kairc::PeerRecord unanchored = kairc::PeerRecord::create(
        network, unknown, 1, now, now + kairc::kPeerRecordMaximumLifetimeSeconds, 0, {});
    check(directory.insert(unanchored, now) == kairc::PeerRecordInsertStatus::unanchored_tombstone,
          "a never-seen identity cannot poison routing buckets with a tombstone");
    const kairc::PeerRecord unverified_live =
        kairc::PeerRecord::create(network, unknown, 2, now, now + kairc::kPeerRecordLifetimeSeconds,
                                  kairc::kPeerCapabilityEventGossip, {second});
    const kairc::PeerRecord unverified_withdrawal = kairc::PeerRecord::create(
        network, unknown, 3, now, now + kairc::kPeerRecordMaximumLifetimeSeconds, 0, {});
    check(directory.insert(unverified_live, now) == kairc::PeerRecordInsertStatus::inserted &&
              directory.insert(unverified_withdrawal, now) ==
                  kairc::PeerRecordInsertStatus::unanchored_tombstone,
          "an unverified live endpoint cannot anchor a propagated withdrawal");

    kairc::crypto::Identity expiring_identity = kairc::crypto::Identity::generate();
    const kairc::PeerRecord expiring = kairc::PeerRecord::create(
        network, expiring_identity, 1, now, now + 1, kairc::kPeerCapabilityEventGossip, {second});
    check(expiring.time_window_is_valid(now) && !expiring.time_window_is_valid(now + 2) &&
              directory.insert(expiring, now) == kairc::PeerRecordInsertStatus::inserted &&
              directory.find(expiring.identity, now).has_value() &&
              !directory.find(expiring.identity, now + 2).has_value(),
          "signed absolute expiry removes a record even before its monotonic deadline elapses");

    const auto path = temporary_database("peer-records");
    {
        kairc::EventStore store(path, network);
        check(store.store_peer_record(record, now, false) == kairc::PeerRecordStoreStatus::stored &&
                  store.store_peer_record(record, now, false) ==
                      kairc::PeerRecordStoreStatus::duplicate,
              "peer record persistence recognizes an exact replay");
        check(store.mark_peer_record_verified(record.identity, record.sequence, now) &&
                  store.peer_record_has_verified_history(record.identity),
              "successful endpoint verification durably anchors later withdrawals");
        check(store.store_peer_record(stale, now, false) == kairc::PeerRecordStoreStatus::stale &&
                  store.store_peer_record(equivocation, now, false) ==
                      kairc::PeerRecordStoreStatus::equivocation,
              "persistent peer-record high-water rejects rollback and equivocation");
        check(store.store_peer_record(tombstone, now, false) ==
                      kairc::PeerRecordStoreStatus::stored &&
                  store.load_peer_records(now).size() == 1,
              "peer record tombstones replace live records durably");
        kairc::PeerDirectory restored(network, local.public_key);
        check(restored.insert(tombstone, now,
                              kairc::PeerRecordAdmission{
                                  .identity_anchored =
                                      store.peer_record_has_verified_history(tombstone.identity),
                              }) == kairc::PeerRecordInsertStatus::inserted &&
                  restored.closest(restored.local_node_id(), 8, now).size() == 1,
              "a persisted verified anchor restores withdrawal propagation after restart");
        const kairc::PeerRecord revived = kairc::PeerRecord::create(
            network, remote, 12, now, now + kairc::kPeerRecordLifetimeSeconds,
            kairc::kPeerCapabilityEventGossip, {first});
        check(store.store_peer_record(revived, now, false) == kairc::PeerRecordStoreStatus::stored,
              "a higher live record can supersede a withdrawal");
        store.prune_peer_records(now + kairc::kPeerRecordLifetimeSeconds + 1);
        check(store.load_peer_records(now + kairc::kPeerRecordLifetimeSeconds + 1).empty() &&
                  store.store_peer_record(tombstone, now + kairc::kPeerRecordLifetimeSeconds + 1,
                                          false) == kairc::PeerRecordStoreStatus::stale,
              "expired routes retain a durable rollback watermark while older records are valid");
        const std::uint64_t first_sequence = store.next_peer_record_sequence(local.public_key, 100);
        const std::uint64_t second_sequence = store.next_peer_record_sequence(local.public_key, 50);
        check(first_sequence == 100 && second_sequence == 101,
              "local peer-record sequence remains monotonic across refreshes");
    }
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

void test_peer_record_storage_quotas() {
    const auto path = temporary_database("peer-record-quota");
    const kairc::Hash network = kairc::network_hash("peer-record-quota-testnet", 4);
    const std::uint64_t now = kairc::unix_time_ms() / 1'000ULL;
    {
        kairc::EventStore store(path, network);
        bool accepted_untrusted = true;
        for (std::size_t index = 0; index < kairc::kMaximumUntrustedStoredPeerRecords; ++index) {
            const kairc::PeerRecord record = make_stored_peer_record(network, index + 1, 1, now);
            accepted_untrusted &=
                store.store_peer_record(record, now, false) == kairc::PeerRecordStoreStatus::stored;
        }
        check(accepted_untrusted, "durable peer store accepts its bounded untrusted partition");

        store.prune_peer_records(now + 2);
        const kairc::PeerRecord untrusted_overflow =
            make_stored_peer_record(network, kairc::kMaximumUntrustedStoredPeerRecords + 1, 1, now);
        check(store.store_peer_record(untrusted_overflow, now, false) ==
                  kairc::PeerRecordStoreStatus::quota_exceeded,
              "short-lived Sybil watermarks cannot consume the trusted reserve");

        bool accepted_retiring_trusted = true;
        constexpr std::uint64_t retiring_identity_base = 50'000;
        for (std::size_t index = 0; index < kairc::kRetiringTrustedPeerRecordReserve; ++index) {
            const kairc::PeerRecord record =
                make_stored_peer_record(network, retiring_identity_base + index, 1, now);
            accepted_retiring_trusted &=
                store.store_peer_record(record, now, true) == kairc::PeerRecordStoreStatus::stored;
        }
        check(accepted_retiring_trusted,
              "one retiring trusted generation has bounded watermark headroom");
        const kairc::PeerRecord retired_refresh =
            make_stored_peer_record(network, retiring_identity_base, 2, now);
        check(store.store_peer_record(retired_refresh, now, false) ==
                  kairc::PeerRecordStoreStatus::protected_downgrade,
              "a removed trusted key cannot indefinitely refresh its protected watermark");

        bool accepted_trusted = true;
        constexpr std::uint64_t trusted_identity_base = 100'000;
        for (std::size_t index = 0; index < kairc::kMaximumConfiguredTrustedPeerRecords; ++index) {
            const kairc::PeerRecord record =
                make_stored_peer_record(network, trusted_identity_base + index, 1, now);
            accepted_trusted &=
                store.store_peer_record(record, now, true) == kairc::PeerRecordStoreStatus::stored;
        }
        check(accepted_trusted, "all configured-trusted identities retain durable capacity");

        bool accepted_local_history = true;
        constexpr std::uint64_t local_identity_base = 200'000;
        for (std::size_t index = 0; index < kairc::kMaximumLocalPeerRecordIdentities; ++index) {
            const kairc::PeerRecord record =
                make_stored_peer_record(network, local_identity_base + index, 1, now);
            accepted_local_history &=
                store.store_peer_record(record, now, true) == kairc::PeerRecordStoreStatus::stored;
        }
        check(accepted_local_history,
              "a retiring and current trusted set cannot block bounded local identity rotation");

        const kairc::PeerRecord trusted_overflow = make_stored_peer_record(
            network, local_identity_base + kairc::kMaximumLocalPeerRecordIdentities, 1, now);
        check(store.store_peer_record(trusted_overflow, now, true) ==
                  kairc::PeerRecordStoreStatus::quota_exceeded,
              "the trusted reserve preserves the peer-record hard disk bound");

        const kairc::PeerRecord existing_update = make_stored_peer_record(network, 1, 2, now);
        check(store.store_peer_record(existing_update, now, false) ==
                  kairc::PeerRecordStoreStatus::stored,
              "an existing identity can advance its durable watermark at total capacity");

        constexpr std::uint64_t watermark_horizon =
            kairc::kPeerRecordMaximumLifetimeSeconds + kairc::kPeerRecordFutureSkewSeconds;
        const std::uint64_t after_watermark = now + watermark_horizon + 1;
        store.prune_peer_records(after_watermark);
        const kairc::PeerRecord retired_after_prune =
            make_stored_peer_record(network, retiring_identity_base, 2, after_watermark);
        check(store.store_peer_record(retired_after_prune, after_watermark, false) ==
                  kairc::PeerRecordStoreStatus::stored,
              "a retired protected slot becomes ordinary only after its watermark ages out");
    }
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

void test_event_store() {
    const auto path = temporary_database("store");
    const auto network = kairc::network_hash("testnet", 4);
    const auto channel = kairc::Channel::public_channel("#test", network);
    {
        kairc::EventStore store(path, network);
        const auto epoch = kairc::unix_time_ms() / kairc::kEpochMilliseconds;
        const kairc::Event first =
            make_event(network, {kairc::epoch_root(network, epoch)}, channel.tag(), "a", "one");
        check(store.insert(first) == kairc::InsertStatus::inserted,
              "event store inserts an epoch-root event");
        const kairc::Event second = make_event(network, {first.id}, channel.tag(), "b", "two");
        check(store.insert(second) == kairc::InsertStatus::inserted,
              "event store inserts an event with parent closure");
        check(store.canonical_layer(first.id) == 1 && store.canonical_layer(second.id) == 2,
              "event store derives causal canonical layers from parent closure");
        check(store.size() == 2, "event store counts inserted events");
        const auto tips = store.tips(epoch, 4);
        check(tips.size() == 1 && tips.front() == second.id, "event graph advances its tip");
        auto missing_parent = kairc::crypto::hash("missing", "parent");
        const kairc::Event orphan =
            make_event(network, {missing_parent}, channel.tag(), "c", "orphan");
        check(store.insert(orphan) == kairc::InsertStatus::missing_parent,
              "event store rejects missing-parent bodies");
    }
    bool rejected_reuse = false;
    try {
        kairc::EventStore wrong_network(path, kairc::network_hash("another-testnet", 4));
    } catch (const kairc::Error &) {
        rejected_reuse = true;
    }
    check(rejected_reuse, "event store cannot be reused across networks");
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

void test_event_store_quotas() {
    const auto path = temporary_database("quota");
    const auto network = kairc::network_hash("quota-testnet", 4);
    const auto channel = kairc::Channel::public_channel("#test", network);
    {
        kairc::EventStoreOptions options;
        options.max_bytes = 16ULL * 1024ULL * 1024ULL;
        options.max_events_per_epoch = 1;
        kairc::EventStore store(path, network, options);
        const auto epoch = kairc::unix_time_ms() / kairc::kEpochMilliseconds;
        const kairc::Event first =
            make_event(network, {kairc::epoch_root(network, epoch)}, channel.tag(), "a", "one");
        const kairc::Event second =
            make_event(network, {kairc::epoch_root(network, epoch)}, channel.tag(), "b", "two");
        check(store.insert(first) == kairc::InsertStatus::inserted,
              "event store accepts an event below its epoch quota");
        check(store.insert(second) == kairc::InsertStatus::quota_exceeded,
              "event store rejects an event above its epoch quota");
        check(store.storage_bytes() > 0 && store.storage_bytes() <= options.max_bytes,
              "event store reports bounded on-disk use");
        store.checkpoint(true);
    }
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}

void test_node_and_parser() {
    const auto path = temporary_database("node");
    {
        kairc::NodeOptions options;
        options.network_id = "node-test";
        options.work_bits = 4;
        options.pending_limit = 4;
        options.pending_per_peer_limit = 1;
        kairc::Node node(path, options);
        const auto secret = kairc::crypto::random_bytes(32);
        node.register_private_channel("#private", secret);
        bool rejected_secret_reuse = false;
        try {
            node.register_private_channel("#other-name", secret);
        } catch (const kairc::Error &) {
            rejected_secret_reuse = true;
        }
        check(rejected_secret_reuse,
              "one private-channel secret cannot map to two local channel names");
        node.register_public_channel("#test");
        int delivered = 0;
        node.set_message_handler([&delivered](const kairc::DeliveredMessage &message) {
            if (message.channel == "#private" && message.text == "hello") {
                ++delivered;
            }
        });
        const auto event = node.publish("#private", "anon", "hello");
        check(delivered == 1, "node delivers a locally accepted encrypted event");
        check(node.load(event.id).has_value(), "node persists a published event");
        check(node.ingest(event, false).status == kairc::IngestStatus::duplicate,
              "node rejects an exact replay before accepting it again");

        const auto graph_channel = kairc::Channel::public_channel("#test", node.network());
        const auto epoch = kairc::unix_time_ms() / kairc::kEpochMilliseconds;
        const kairc::Event parent =
            make_event(node.network(), {kairc::epoch_root(node.network(), epoch)},
                       graph_channel.tag(), "parent", "first");
        const kairc::Event child =
            make_event(node.network(), {parent.id}, graph_channel.tag(), "child", "second");
        const auto pending = node.ingest(child, false);
        check(pending.status == kairc::IngestStatus::pending_parents &&
                  pending.missing.size() == 1 && pending.missing.front() == parent.id,
              "node holds a child until its parent arrives");
        const auto resolved = node.ingest(parent, false);
        check(resolved.status == kairc::IngestStatus::accepted && resolved.accepted.size() == 2 &&
                  node.load(child.id).has_value(),
              "parent arrival commits the bounded pending closure");

        const kairc::Event delayed_parent =
            make_event(node.network(), {kairc::epoch_root(node.network(), epoch)},
                       graph_channel.tag(), "parent", "shared dependency");
        const kairc::Event valid_sibling =
            make_event(node.network(), {delayed_parent.id}, graph_channel.tag(), "child", "valid");
        const std::uint64_t prior_epoch_timestamp = epoch * kairc::kEpochMilliseconds - 1;
        const kairc::Event cross_epoch_child =
            make_event(node.network(), {delayed_parent.id}, graph_channel.tag(), "child", "invalid",
                       4, prior_epoch_timestamp);
        check(node.ingest(cross_epoch_child, false).status ==
                      kairc::IngestStatus::pending_parents &&
                  node.ingest(valid_sibling, false).status == kairc::IngestStatus::pending_parents,
              "pending children may share an as-yet unknown parent");
        const auto siblings_resolved = node.ingest(delayed_parent, false);
        check(siblings_resolved.status == kairc::IngestStatus::accepted &&
                  node.load(valid_sibling.id).has_value() &&
                  !node.load(cross_epoch_child.id).has_value(),
              "an invalid cross-epoch child cannot strand a valid pending sibling");

        kairc::PublicKey peer{};
        peer.fill(0x42);
        const auto missing_one = kairc::crypto::hash("missing", "one");
        const auto missing_two = kairc::crypto::hash("missing", "two");
        const kairc::Event remote_one =
            make_event(node.network(), {missing_one}, graph_channel.tag(), "peer", "one");
        const kairc::Event remote_two =
            make_event(node.network(), {missing_two}, graph_channel.tag(), "peer", "two");
        check(node.ingest_peer(remote_one, peer, false).status ==
                  kairc::IngestStatus::pending_parents,
              "remote peer may consume its first pending slot");
        const auto peer_limited = node.ingest_peer(remote_two, peer, false);
        check(peer_limited.status == kairc::IngestStatus::rejected &&
                  peer_limited.error == "peer pending-event limit reached",
              "one peer cannot monopolize the global pending queue");
    }
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");

    const auto command = kairc::parse_irc_line("PRIVMSG #room :hello world");
    check(command.name == "PRIVMSG" && command.parameters.size() == 2 &&
              command.parameters[1] == "hello world",
          "IRC parser handles a trailing parameter");
}

void test_endpoints() {
    const auto tor = kairc::parse_host_port("127.0.0.1:9050");
    const auto endpoint = kairc::parse_peer_endpoint("tor://example.onion:7777", tor);
    check(endpoint.transport == kairc::PeerTransport::socks5 && endpoint.proxy &&
              endpoint.target.host == "example.onion" && endpoint.target.port == 7777,
          "tor peer routes through SOCKS5 without local DNS");
    bool rejected_direct_onion = false;
    try {
        static_cast<void>(kairc::parse_peer_endpoint("tcp://example.onion:7777", tor));
    } catch (const kairc::Error &) {
        rejected_direct_onion = true;
    }
    check(rejected_direct_onion, "direct TCP refuses .onion targets that could leak into DNS");
    check(kairc::is_loopback_host("::1") && !kairc::is_loopback_host("0.0.0.0") &&
              !kairc::is_loopback_host("localhost"),
          "local IRC boundary recognizes loopback addresses");
    const auto advertised = kairc::parse_advertised_peer_uri("tor://" + test_onion('a') + ":7777");
    check(advertised.host == test_onion('a') && advertised.port == 7777,
          "discovery accepts only an explicit canonical onion-v3 target");
    bool rejected_discovery_dns = false;
    try {
        static_cast<void>(kairc::parse_advertised_peer_uri("tor://example.onion:7777"));
    } catch (const kairc::Error &) {
        rejected_discovery_dns = true;
    }
    check(rejected_discovery_dns,
          "discovery rejects non-v3 onion and arbitrary DNS advertisements");
}

void test_peer_identity_configuration() {
    kairc::Key seed{};
    seed.fill(0x0a);
    const kairc::crypto::Identity identity = kairc::crypto::Identity::from_seed(seed);
    check(kairc::hex(identity.public_key) ==
              "43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c",
          "peer identity seed derives a stable Ed25519 public key");

    kairc::Config unsafe;
    unsafe.peer_uris.push_back("tcp://127.0.0.1:7777");
    bool rejected_unpinned_peer = false;
    try {
        unsafe.finalize();
    } catch (const kairc::Error &) {
        rejected_unpinned_peer = true;
    }
    check(rejected_unpinned_peer,
          "P2P configuration rejects an unpinned peer without explicit opt-in");

    kairc::Config pinned_bootstrap;
    pinned_bootstrap.p2p_identity_seed = seed;
    pinned_bootstrap.bootstrap_peers.push_back(kairc::BootstrapPeerConfig{
        .identity = kairc::fixed_bytes<32>(
            kairc::unhex("66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"),
            "test bootstrap identity"),
        .uri = "tcp://127.0.0.1:7777",
    });
    pinned_bootstrap.finalize();
    check(pinned_bootstrap.peers.size() == 1 &&
              pinned_bootstrap.peers.front().expected_identity.has_value() &&
              pinned_bootstrap.trusted_peer_keys.size() == 1,
          "bootstrap_peer binds one endpoint to its expected trusted identity");

    kairc::Config unbounded_handshakes;
    unbounded_handshakes.peer_limits.authenticated_handshakes_per_minute = 0;
    bool rejected_unbounded_handshakes = false;
    try {
        unbounded_handshakes.finalize();
    } catch (const kairc::Error &) {
        rejected_unbounded_handshakes = true;
    }
    check(rejected_unbounded_handshakes,
          "P2P configuration rejects a disabled authenticated-handshake budget");

    kairc::Config trusted_discovery;
    trusted_discovery.p2p_identity_seed = seed;
    trusted_discovery.tor_proxy = kairc::HostPort{"127.0.0.1", 9050};
    trusted_discovery.discovery.mode = kairc::DiscoveryMode::trusted;
    bool rejected_trusted_without_keys = false;
    try {
        trusted_discovery.finalize();
    } catch (const kairc::Error &) {
        rejected_trusted_without_keys = true;
    }
    check(rejected_trusted_without_keys,
          "trusted discovery requires an explicit identity allowlist");

    kairc::Config open_advertiser;
    open_advertiser.p2p_identity_seed = seed;
    open_advertiser.p2p_listen = kairc::HostPort{"127.0.0.1", 7777};
    open_advertiser.tor_proxy = kairc::HostPort{"127.0.0.1", 9050};
    open_advertiser.discovery.mode = kairc::DiscoveryMode::open;
    open_advertiser.discovery.advertised_endpoints = {{test_onion('a'), 7777}};
    bool rejected_closed_advertiser = false;
    try {
        open_advertiser.finalize();
    } catch (const kairc::Error &) {
        rejected_closed_advertiser = true;
    }
    check(rejected_closed_advertiser,
          "open discovery cannot advertise while rejecting every unknown inbound identity");
    open_advertiser.allow_unknown_inbound = true;
    open_advertiser.finalize();
}

} // namespace

int main() {
    try {
        kairc::crypto::initialize();
        test_channel_crypto();
        test_signed_event();
        test_peer_discovery_records();
        test_peer_record_storage_quotas();
        test_event_store();
        test_event_store_quotas();
        test_node_and_parser();
        test_endpoints();
        test_peer_identity_configuration();
    } catch (const std::exception &exception) {
        std::cerr << "UNCAUGHT: " << exception.what() << '\n';
        return 1;
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "all tests passed\n";
    return 0;
}
