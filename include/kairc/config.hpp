#pragma once

#include "kairc/discovery.hpp"
#include "kairc/node.hpp"

#include <filesystem>
#include <optional>

namespace kairc {

struct HostPort {
    std::string host;
    std::uint16_t port = 0;
};

enum class PeerTransport : std::uint8_t {
    direct_tcp,
    socks5,
};

struct PeerEndpoint {
    PeerTransport transport = PeerTransport::direct_tcp;
    HostPort target;
    std::optional<HostPort> proxy;
    std::optional<PublicKey> expected_identity;
};

struct BootstrapPeerConfig {
    PublicKey identity{};
    std::string uri;
};

struct ChannelConfig {
    std::string name;
    std::optional<Key> secret;

    ~ChannelConfig() {
        if (secret) {
            crypto::wipe(*secret);
        }
    }
};

struct PeerLimits {
    std::uint64_t authenticated_handshakes_per_minute = 12;
    std::uint64_t global_authenticated_handshakes_per_minute = 120;
    std::uint64_t bytes_per_minute = 8ULL * 1024ULL * 1024ULL;
    std::uint64_t frames_per_minute = 600;
    std::uint64_t events_per_minute = 120;
    std::uint64_t global_bytes_per_minute = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t global_frames_per_minute = 4'800;
    std::uint64_t global_events_per_minute = 960;
    std::uint64_t idle_timeout_seconds = 120;
};

struct Config {
    HostPort irc_listen{"127.0.0.1", 6667};
    std::optional<HostPort> p2p_listen;
    std::optional<HostPort> tor_proxy;
    std::vector<std::string> peer_uris;
    std::vector<BootstrapPeerConfig> bootstrap_peers;
    std::vector<PeerEndpoint> peers;
    std::optional<Key> p2p_identity_seed;
    std::vector<PublicKey> trusted_peer_keys;
    bool allow_unknown_inbound = false;
    bool allow_unknown_outbound = false;
    PeerDiscoveryOptions discovery;
    std::filesystem::path database = "./data/kairc.db";
    NodeOptions node;
    PeerLimits peer_limits;
    std::vector<ChannelConfig> channels{{"#lobby", std::nullopt}};

    Config() = default;
    ~Config();
    Config(const Config &) = delete;
    Config &operator=(const Config &) = delete;
    Config(Config &&) noexcept = default;
    Config &operator=(Config &&) noexcept = default;

    static Config load(const std::filesystem::path &path);
    void finalize();
};

HostPort parse_host_port(std::string_view value);
PeerEndpoint parse_peer_endpoint(std::string_view uri, const std::optional<HostPort> &tor_proxy);
bool is_loopback_host(std::string_view host);

} // namespace kairc
