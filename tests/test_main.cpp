#include "kairc/channel.hpp"
#include "kairc/config.hpp"
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
                        std::uint8_t work_bits = 4) {
    const kairc::Channel room = kairc::Channel::public_channel("#test", network);
    kairc::crypto::Identity identity = kairc::crypto::Identity::generate();
    kairc::Event event;
    event.network = network;
    event.timestamp_ms = kairc::unix_time_ms();
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
    event.content[0] ^= 1;
    check(!event.verify(network, 4, kairc::unix_time_ms(), nullptr), "tampered event is rejected");
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

void test_node_and_parser() {
    const auto path = temporary_database("node");
    {
        kairc::NodeOptions options;
        options.network_id = "node-test";
        options.work_bits = 4;
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
}

} // namespace

int main() {
    try {
        kairc::crypto::initialize();
        test_channel_crypto();
        test_signed_event();
        test_event_store();
        test_node_and_parser();
        test_endpoints();
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
