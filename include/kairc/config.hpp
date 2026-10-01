#pragma once

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

struct Config {
    HostPort irc_listen{"127.0.0.1", 6667};
    std::optional<HostPort> p2p_listen;
    std::optional<HostPort> tor_proxy;
    std::vector<std::string> peer_uris;
    std::vector<PeerEndpoint> peers;
    std::filesystem::path database = "./data/kairc.db";
    NodeOptions node;
    std::vector<ChannelConfig> channels{{"#lobby", std::nullopt}};

    static Config load(const std::filesystem::path &path);
    void finalize();
};

HostPort parse_host_port(std::string_view value);
PeerEndpoint parse_peer_endpoint(std::string_view uri, const std::optional<HostPort> &tor_proxy);
bool is_loopback_host(std::string_view host);

} // namespace kairc
