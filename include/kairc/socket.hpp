#pragma once

#include "kairc/config.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>

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
    std::optional<Socket> accept_until(std::chrono::steady_clock::time_point deadline) const;
    std::optional<std::string> peer_rate_key() const;
    void send_all(std::span<const Byte> data) const;
    void send_all_until(std::span<const Byte> data,
                        std::chrono::steady_clock::time_point deadline) const;
    std::optional<std::size_t> send_some(std::span<const Byte> data) const;
    bool receive_exact(std::span<Byte> output) const;
    bool receive_exact_until(std::span<Byte> output,
                             std::chrono::steady_clock::time_point deadline) const;
    std::optional<std::size_t> receive_some(std::span<Byte> output) const;
    std::optional<std::string> receive_line(std::size_t maximum) const;
    void set_send_timeout(int seconds) const;
    void set_receive_timeout(int seconds) const;

    bool valid() const;
    void close() noexcept;

  private:
    std::shared_ptr<SocketState> state_;
};

} // namespace kairc
