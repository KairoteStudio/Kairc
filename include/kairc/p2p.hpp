#pragma once

#include "kairc/config.hpp"

#include <memory>

namespace kairc {

class Node;

class PeerNetwork {
  public:
    PeerNetwork(Node &node, std::optional<HostPort> listen, std::vector<PeerEndpoint> peers,
                PeerLimits limits = {}, const std::optional<Key> &identity_seed = std::nullopt,
                std::vector<PublicKey> trusted_peer_keys = {}, bool allow_unknown_inbound = false,
                bool allow_unknown_outbound = false, PeerDiscoveryOptions discovery = {},
                std::optional<HostPort> tor_proxy = std::nullopt);
    ~PeerNetwork();

    PeerNetwork(const PeerNetwork &) = delete;
    PeerNetwork &operator=(const PeerNetwork &) = delete;

    void start();
    void stop();
    void broadcast(const Event &event);
    std::size_t connected_peers() const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace kairc
