#include "kairc/config.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <limits>
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

void wipe_string(std::string &value) noexcept {
    crypto::wipe(std::span<Byte>(reinterpret_cast<Byte *>(value.data()), value.size()));
}

Key parse_secret_key(std::string &value, std::string_view label) {
    struct StringWiper {
        std::string &value;
        ~StringWiper() {
            wipe_string(value);
        }
    } string_wiper{value};
    Bytes decoded = unhex(value);
    struct BytesWiper {
        Bytes &value;
        ~BytesWiper() {
            crypto::wipe(value);
        }
    } bytes_wiper{decoded};
    return fixed_bytes<32>(decoded, label);
}

std::uint64_t parse_integer(std::string_view value, std::string_view key) {
    std::uint64_t output = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), output);
    if (error != std::errc{} || end != value.data() + value.size()) {
        throw Error("configuration value for " + std::string(key) + " must be an integer");
    }
    return output;
}

bool parse_boolean(std::string_view value, std::string_view key) {
    if (value == "true") {
        return true;
    }
    if (value == "false") {
        return false;
    }
    throw Error("configuration value for " + std::string(key) + " must be true or false");
}

DiscoveryMode parse_discovery_mode(std::string_view value) {
    if (value == "off") {
        return DiscoveryMode::off;
    }
    if (value == "trusted") {
        return DiscoveryMode::trusted;
    }
    if (value == "open") {
        return DiscoveryMode::open;
    }
    throw Error("peer_discovery must be off, trusted, or open");
}

std::uint64_t mebibytes(std::uint64_t value, std::string_view key) {
    constexpr std::uint64_t scale = 1024ULL * 1024ULL;
    if (value > std::numeric_limits<std::uint64_t>::max() / scale) {
        throw Error("configuration value for " + std::string(key) + " is too large");
    }
    return value * scale;
}

void validate_peer_limits(const PeerLimits &limits) {
    constexpr std::uint64_t maximum_bytes_per_minute = 16ULL * 1024ULL * 1024ULL * 1024ULL;
    constexpr std::uint64_t maximum_items_per_minute = 10'000'000;
    if (limits.authenticated_handshakes_per_minute == 0 ||
        limits.authenticated_handshakes_per_minute > maximum_items_per_minute) {
        throw Error("peer_authenticated_handshakes_per_minute must be between 1 and 10000000");
    }
    if (limits.global_authenticated_handshakes_per_minute == 0 ||
        limits.global_authenticated_handshakes_per_minute > maximum_items_per_minute) {
        throw Error("global_authenticated_handshakes_per_minute must be between 1 and 10000000");
    }
    if (limits.bytes_per_minute == 0 || limits.bytes_per_minute > maximum_bytes_per_minute ||
        limits.global_bytes_per_minute == 0 ||
        limits.global_bytes_per_minute > maximum_bytes_per_minute) {
        throw Error("peer byte budgets must be between 1 and 17179869184 bytes per minute");
    }
    if (limits.frames_per_minute == 0 || limits.frames_per_minute > maximum_items_per_minute ||
        limits.global_frames_per_minute == 0 ||
        limits.global_frames_per_minute > maximum_items_per_minute) {
        throw Error("peer frame budgets must be between 1 and 10000000 per minute");
    }
    if (limits.events_per_minute == 0 || limits.events_per_minute > maximum_items_per_minute ||
        limits.global_events_per_minute == 0 ||
        limits.global_events_per_minute > maximum_items_per_minute) {
        throw Error("peer event budgets must be between 1 and 10000000 per minute");
    }
    if (limits.idle_timeout_seconds < 10 || limits.idle_timeout_seconds > 86'400) {
        throw Error("peer_idle_timeout_seconds must be between 10 and 86400");
    }
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

Config::~Config() {
    if (p2p_identity_seed) {
        crypto::wipe(*p2p_identity_seed);
    }
}

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
        return PeerEndpoint{
            .transport = PeerTransport::direct_tcp,
            .target = std::move(target),
            .proxy = std::nullopt,
            .expected_identity = std::nullopt,
        };
    }
    if (uri.starts_with(tor_prefix)) {
        if (!tor_proxy) {
            throw Error("tor:// peer requires tor_proxy in the configuration");
        }
        return PeerEndpoint{
            .transport = PeerTransport::socks5,
            .target = parse_host_port(uri.substr(tor_prefix.size())),
            .proxy = tor_proxy,
            .expected_identity = std::nullopt,
        };
    }
    if (uri.starts_with(socks_prefix)) {
        const std::string_view rest = uri.substr(socks_prefix.size());
        const auto slash = rest.find('/');
        if (slash == std::string_view::npos) {
            throw Error("socks5 peer must be socks5://proxy:port/target:port");
        }
        return PeerEndpoint{
            .transport = PeerTransport::socks5,
            .target = parse_host_port(rest.substr(slash + 1)),
            .proxy = parse_host_port(rest.substr(0, slash)),
            .expected_identity = std::nullopt,
        };
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
        std::string cleaned = trim(line);
        if (cleaned.empty() || cleaned.starts_with('#') || cleaned.starts_with(';')) {
            continue;
        }
        const auto equal = cleaned.find('=');
        if (equal == std::string::npos) {
            throw Error("configuration line " + std::to_string(line_number) + " has no '='");
        }
        std::string key = trim(std::string_view(cleaned).substr(0, equal));
        std::string value = unquote(trim(std::string_view(cleaned).substr(equal + 1)));
        struct ParsedLineWiper {
            std::string &line;
            std::string &cleaned;
            std::string &key;
            std::string &value;
            ~ParsedLineWiper() {
                wipe_string(line);
                wipe_string(cleaned);
                wipe_string(key);
                wipe_string(value);
            }
        } parsed_line_wiper{line, cleaned, key, value};
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
            } else if (key == "bootstrap_peer") {
                const auto separator = value.find('@');
                if (separator == std::string::npos || separator == 0 ||
                    separator + 1 == value.size()) {
                    throw Error("bootstrap_peer must be PUBLIC_KEY@transport://host:port");
                }
                config.bootstrap_peers.push_back(BootstrapPeerConfig{
                    .identity = fixed_bytes<32>(unhex(value.substr(0, separator)),
                                                "bootstrap peer public key"),
                    .uri = value.substr(separator + 1),
                });
            } else if (key == "p2p_identity_seed") {
                if (config.p2p_identity_seed) {
                    throw Error("P2P identity seed is configured more than once");
                }
                config.p2p_identity_seed = parse_secret_key(value, "P2P identity seed");
            } else if (key == "trusted_peer") {
                config.trusted_peer_keys.push_back(
                    fixed_bytes<32>(unhex(value), "trusted peer public key"));
            } else if (key == "allow_unknown_inbound") {
                config.allow_unknown_inbound = parse_boolean(value, key);
            } else if (key == "allow_unknown_outbound") {
                config.allow_unknown_outbound = parse_boolean(value, key);
            } else if (key == "peer_discovery") {
                config.discovery.mode = parse_discovery_mode(value);
            } else if (key == "advertise_peer") {
                config.discovery.advertised_endpoints.push_back(parse_advertised_peer_uri(value));
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
            } else if (key == "max_store_mib") {
                config.node.max_store_bytes = mebibytes(parse_integer(value, key), key);
            } else if (key == "max_events_per_epoch") {
                config.node.max_events_per_epoch = parse_integer(value, key);
            } else if (key == "verification_workers") {
                config.node.verification_workers = parse_integer(value, key);
            } else if (key == "presentation_delay_ms") {
                config.node.presentation_delay_ms = parse_integer(value, key);
            } else if (key == "pending_per_peer_limit") {
                config.node.pending_per_peer_limit = parse_integer(value, key);
            } else if (key == "pending_ttl_seconds") {
                config.node.pending_ttl_seconds = parse_integer(value, key);
            } else if (key == "peer_bytes_per_minute") {
                config.peer_limits.bytes_per_minute = parse_integer(value, key);
            } else if (key == "peer_authenticated_handshakes_per_minute") {
                config.peer_limits.authenticated_handshakes_per_minute = parse_integer(value, key);
            } else if (key == "global_authenticated_handshakes_per_minute") {
                config.peer_limits.global_authenticated_handshakes_per_minute =
                    parse_integer(value, key);
            } else if (key == "peer_frames_per_minute") {
                config.peer_limits.frames_per_minute = parse_integer(value, key);
            } else if (key == "peer_events_per_minute") {
                config.peer_limits.events_per_minute = parse_integer(value, key);
            } else if (key == "global_peer_bytes_per_minute") {
                config.peer_limits.global_bytes_per_minute = parse_integer(value, key);
            } else if (key == "global_peer_frames_per_minute") {
                config.peer_limits.global_frames_per_minute = parse_integer(value, key);
            } else if (key == "global_peer_events_per_minute") {
                config.peer_limits.global_events_per_minute = parse_integer(value, key);
            } else if (key == "peer_idle_timeout_seconds") {
                config.peer_limits.idle_timeout_seconds = parse_integer(value, key);
            } else if (key.starts_with("channel.")) {
                ChannelConfig channel{canonical_channel(key.substr(8)), std::nullopt};
                if (!value.empty() && value != "public") {
                    channel.secret = parse_secret_key(value, "channel secret");
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
    if (has_private_channel || config.p2p_identity_seed) {
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
            throw Error("configuration containing secret keys must not be accessible by group or "
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
    constexpr std::uint64_t minimum_store_bytes = 16ULL * 1024ULL * 1024ULL;
    constexpr std::uint64_t maximum_store_bytes = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    if (node.max_store_bytes < minimum_store_bytes || node.max_store_bytes > maximum_store_bytes) {
        throw Error("max_store_mib must be between 16 and 1048576");
    }
    if (node.max_events_per_epoch == 0 || node.max_events_per_epoch > 10'000'000) {
        throw Error("max_events_per_epoch must be between 1 and 10000000");
    }
    if (node.verification_workers == 0 || node.verification_workers > 256) {
        throw Error("verification_workers must be between 1 and 256");
    }
    if (node.presentation_delay_ms > 5'000) {
        throw Error("presentation_delay_ms must be between 0 and 5000");
    }
    if (node.pending_per_peer_limit == 0 || node.pending_per_peer_limit > node.pending_limit) {
        throw Error("pending_per_peer_limit must be between 1 and pending_limit");
    }
    if (node.pending_ttl_seconds < 30 || node.pending_ttl_seconds > 3'600) {
        throw Error("pending_ttl_seconds must be between 30 and 3600");
    }
    validate_peer_limits(peer_limits);
    if (database.empty()) {
        throw Error("database path cannot be empty");
    }
    if (peer_uris.size() + bootstrap_peers.size() > 64) {
        throw Error("configuration cannot contain more than 64 static peers");
    }
    peers.clear();
    for (const std::string &uri : peer_uris) {
        peers.push_back(parse_peer_endpoint(uri, tor_proxy));
    }
    for (const BootstrapPeerConfig &bootstrap : bootstrap_peers) {
        PeerEndpoint endpoint = parse_peer_endpoint(bootstrap.uri, tor_proxy);
        endpoint.expected_identity = bootstrap.identity;
        peers.push_back(std::move(endpoint));
        if (std::find(trusted_peer_keys.begin(), trusted_peer_keys.end(), bootstrap.identity) ==
            trusted_peer_keys.end()) {
            trusted_peer_keys.push_back(bootstrap.identity);
        }
    }
    if (trusted_peer_keys.size() > 256) {
        throw Error("configuration cannot contain more than 256 trusted peer keys");
    }
    std::unordered_set<std::string> peer_keys;
    for (const PublicKey &key : trusted_peer_keys) {
        if (!peer_keys.insert(hex(key)).second) {
            throw Error("trusted peer key is configured more than once");
        }
    }
    if (discovery.advertised_endpoints.size() > kMaximumPeerRecordEndpoints) {
        throw Error("configuration cannot advertise more than 1 discovery endpoint");
    }
    std::sort(discovery.advertised_endpoints.begin(), discovery.advertised_endpoints.end());
    if (std::adjacent_find(discovery.advertised_endpoints.begin(),
                           discovery.advertised_endpoints.end()) !=
        discovery.advertised_endpoints.end()) {
        throw Error("advertise_peer is configured more than once");
    }
    if (discovery.mode == DiscoveryMode::off && !discovery.advertised_endpoints.empty()) {
        throw Error("advertise_peer requires peer_discovery = trusted or open");
    }
    if (discovery.mode != DiscoveryMode::off && !tor_proxy) {
        throw Error("peer discovery requires tor_proxy for onion-only discovered peers");
    }
    if (discovery.mode == DiscoveryMode::trusted && trusted_peer_keys.empty()) {
        throw Error("trusted peer discovery requires at least one trusted_peer identity");
    }
    if (!discovery.advertised_endpoints.empty() && !p2p_listen) {
        throw Error("advertise_peer requires a local p2p_listen target for the onion service");
    }
    if (discovery.mode == DiscoveryMode::open && !discovery.advertised_endpoints.empty() &&
        !allow_unknown_inbound) {
        throw Error("open discovery advertisement requires allow_unknown_inbound = true");
    }
    const bool p2p_enabled =
        p2p_listen.has_value() || !peers.empty() || discovery.mode != DiscoveryMode::off;
    if (p2p_enabled && !p2p_identity_seed) {
        throw Error("P2P networking requires p2p_identity_seed; generate one with "
                    "kaircd --gen-peer-identity");
    }
    if (p2p_listen && !allow_unknown_inbound && trusted_peer_keys.empty()) {
        throw Error("an inbound P2P listener requires trusted_peer entries or explicit "
                    "allow_unknown_inbound = true");
    }
    if (!peers.empty() && !allow_unknown_outbound && trusted_peer_keys.empty()) {
        throw Error("outbound P2P requires trusted_peer entries or explicit "
                    "allow_unknown_outbound = true");
    }
    if (p2p_identity_seed) {
        const crypto::Identity identity = crypto::Identity::from_seed(*p2p_identity_seed);
        if (std::find(trusted_peer_keys.begin(), trusted_peer_keys.end(), identity.public_key) !=
            trusted_peer_keys.end()) {
            throw Error("the local P2P identity cannot also be a trusted remote peer");
        }
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
