#include "kairc/config.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <unordered_set>

namespace kairc {

namespace {

std::string trim(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
    }
    return std::string(value);
}

std::string unquote(std::string value) {
    if (value.size() >= 2 && ((value.front() == '"' && value.back() == '"') ||
                              (value.front() == '\'' && value.back() == '\''))) {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

std::uint64_t parse_integer(std::string_view value, std::string_view key) {
    std::uint64_t output = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), output);
    if (error != std::errc{} || end != value.data() + value.size()) {
        throw Error("configuration value for " + std::string(key) + " must be an integer");
    }
    return output;
}

bool is_onion_host(std::string_view host) {
    std::string lower(host);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    if (lower.ends_with('.')) {
        lower.pop_back();
    }
    return lower.ends_with(".onion");
}

} // namespace

HostPort parse_host_port(std::string_view value) {
    value = std::string_view(value.data(), value.size());
    std::string_view host;
    std::string_view port_text;
    if (!value.empty() && value.front() == '[') {
        const auto close = value.find(']');
        if (close == std::string_view::npos || close + 1 >= value.size() ||
            value[close + 1] != ':') {
            throw Error("invalid bracketed host:port address");
        }
        host = value.substr(1, close - 1);
        port_text = value.substr(close + 2);
    } else {
        const auto colon = value.rfind(':');
        if (colon == std::string_view::npos || value.find(':') != colon) {
            throw Error("address must use host:port (bracket IPv6 addresses)");
        }
        host = value.substr(0, colon);
        port_text = value.substr(colon + 1);
    }
    if (host.empty() || port_text.empty()) {
        throw Error("address has an empty host or port");
    }
    unsigned int port = 0;
    const auto [end, error] =
        std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (error != std::errc{} || end != port_text.data() + port_text.size() || port == 0 ||
        port > 65535) {
        throw Error("address has an invalid TCP port");
    }
    return {std::string(host), static_cast<std::uint16_t>(port)};
}

PeerEndpoint parse_peer_endpoint(std::string_view uri, const std::optional<HostPort> &tor_proxy) {
    constexpr std::string_view tcp_prefix = "tcp://";
    constexpr std::string_view tor_prefix = "tor://";
    constexpr std::string_view socks_prefix = "socks5://";
    if (uri.starts_with(tcp_prefix)) {
        HostPort target = parse_host_port(uri.substr(tcp_prefix.size()));
        if (is_onion_host(target.host)) {
            throw Error("an .onion peer must use tor:// or socks5:// to prevent DNS leaks");
        }
        return {PeerTransport::direct_tcp, std::move(target), std::nullopt};
    }
    if (uri.starts_with(tor_prefix)) {
        if (!tor_proxy) {
            throw Error("tor:// peer requires tor_proxy in the configuration");
        }
        return {PeerTransport::socks5, parse_host_port(uri.substr(tor_prefix.size())), tor_proxy};
    }
    if (uri.starts_with(socks_prefix)) {
        const std::string_view rest = uri.substr(socks_prefix.size());
        const auto slash = rest.find('/');
        if (slash == std::string_view::npos) {
            throw Error("socks5 peer must be socks5://proxy:port/target:port");
        }
        return {PeerTransport::socks5, parse_host_port(rest.substr(slash + 1)),
                parse_host_port(rest.substr(0, slash))};
    }
    throw Error("unsupported peer transport; use tor://, socks5://, or tcp://");
}

bool is_loopback_host(std::string_view host) {
    std::string lower(host);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    return lower == "127.0.0.1" || lower == "::1";
}

Config Config::load(const std::filesystem::path &path) {
    std::ifstream input(path);
    if (!input) {
        throw Error("could not open configuration: " + path.string());
    }

    Config config;
    config.channels.clear();
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        const std::string cleaned = trim(line);
        if (cleaned.empty() || cleaned.starts_with('#') || cleaned.starts_with(';')) {
            continue;
        }
        const auto equal = cleaned.find('=');
        if (equal == std::string::npos) {
            throw Error("configuration line " + std::to_string(line_number) + " has no '='");
        }
        const std::string key = trim(std::string_view(cleaned).substr(0, equal));
        const std::string value = unquote(trim(std::string_view(cleaned).substr(equal + 1)));
        try {
            if (key == "irc_listen") {
                config.irc_listen = parse_host_port(value);
            } else if (key == "p2p_listen") {
                config.p2p_listen =
                    value.empty() ? std::nullopt : std::optional(parse_host_port(value));
            } else if (key == "tor_proxy") {
                config.tor_proxy =
                    value.empty() ? std::nullopt : std::optional(parse_host_port(value));
            } else if (key == "peer") {
                config.peer_uris.push_back(value);
            } else if (key == "database") {
                config.database = value;
            } else if (key == "network_id") {
                config.node.network_id = value;
            } else if (key == "work_bits") {
                const auto bits = parse_integer(value, key);
                if (bits > 24) {
                    throw Error("work_bits must be between 0 and 24");
                }
                config.node.work_bits = static_cast<std::uint8_t>(bits);
            } else if (key == "retention_hours") {
                config.node.retention_hours = parse_integer(value, key);
            } else if (key == "pending_limit") {
                config.node.pending_limit = parse_integer(value, key);
            } else if (key.starts_with("channel.")) {
                ChannelConfig channel{canonical_channel(key.substr(8)), std::nullopt};
                if (!value.empty() && value != "public") {
                    const Bytes secret = unhex(value);
                    channel.secret = fixed_bytes<32>(secret, "channel secret");
                }
                config.channels.push_back(std::move(channel));
            } else {
                throw Error("unknown configuration key: " + key);
            }
        } catch (const Error &exception) {
            throw Error("configuration line " + std::to_string(line_number) + ": " +
                        exception.what());
        }
    }
    if (config.channels.empty()) {
        config.channels.push_back({"#lobby", std::nullopt});
    }
    config.finalize();
    const bool has_private_channel =
        std::any_of(config.channels.begin(), config.channels.end(),
                    [](const ChannelConfig &channel) { return channel.secret.has_value(); });
    if (has_private_channel) {
        std::error_code status_error;
        const auto permissions = std::filesystem::status(path, status_error).permissions();
        if (status_error) {
            throw Error("could not verify permissions on configuration containing channel keys: " +
                        status_error.message());
        }
        constexpr auto exposed =
            std::filesystem::perms::group_read | std::filesystem::perms::group_write |
            std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
            std::filesystem::perms::others_write | std::filesystem::perms::others_exec;
        if ((permissions & exposed) != std::filesystem::perms::none) {
            throw Error("configuration containing channel keys must not be accessible by group or "
                        "others (use chmod 600)");
        }
    }
    return config;
}

void Config::finalize() {
    if (!is_loopback_host(irc_listen.host)) {
        throw Error("irc_listen must use literal 127.0.0.1 or ::1: the IRC gateway is a local "
                    "trust boundary");
    }
    if (node.work_bits > 24) {
        throw Error("work_bits must be between 0 and 24");
    }
    if (node.network_id.empty() || node.network_id.size() > 128) {
        throw Error("network_id must contain between 1 and 128 bytes");
    }
    if (node.retention_hours == 0 || node.retention_hours > 24ULL * 365ULL) {
        throw Error("retention_hours must be between 1 and 8760");
    }
    if (node.pending_limit == 0 || node.pending_limit > 65536) {
        throw Error("pending_limit must be between 1 and 65536");
    }
    if (database.empty()) {
        throw Error("database path cannot be empty");
    }
    if (peer_uris.size() > 64) {
        throw Error("configuration cannot contain more than 64 static peers");
    }
    peers.clear();
    for (const std::string &uri : peer_uris) {
        peers.push_back(parse_peer_endpoint(uri, tor_proxy));
    }
    std::unordered_set<std::string> channel_names;
    if (channels.size() > 1024) {
        throw Error("configuration cannot contain more than 1024 local channels");
    }
    for (const ChannelConfig &channel : channels) {
        if (!channel_names.insert(canonical_channel(channel.name)).second) {
            throw Error("channel configured more than once: " + channel.name);
        }
    }
}

} // namespace kairc
