#pragma once

#include "kairc/config.hpp"

#include <atomic>
#include <memory>
#include <optional>

namespace kairc {

struct SocketState;

class Socket {
  public:
    Socket() = default;
    explicit Socket(int descriptor);
    ~Socket();

    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;
    Socket(Socket &&other) noexcept;
    Socket &operator=(Socket &&other) noexcept;

    static Socket connect_tcp(const HostPort &address);
    static Socket connect_peer(const PeerEndpoint &endpoint);
    static Socket listen_tcp(const HostPort &address, int backlog = 64);

    Socket accept() const;
    void send_all(std::span<const Byte> data) const;
    bool receive_exact(std::span<Byte> output) const;
    std::optional<std::string> receive_line(std::size_t maximum) const;
    void set_send_timeout(int seconds) const;
    void set_receive_timeout(int seconds) const;

    bool valid() const;
    void close() noexcept;

  private:
    std::shared_ptr<SocketState> state_;
};

} // namespace kairc
