#include "kairc/socket.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <system_error>
#include <unistd.h>

namespace kairc {

struct SocketState {
    explicit SocketState(int descriptor_value) : descriptor(descriptor_value) {}

    std::mutex mutex;
    std::condition_variable changed;
    int descriptor = -1;
    std::size_t active_operations = 0;
    bool closing = false;
};

namespace {

class SocketOperation {
  public:
    explicit SocketOperation(const std::shared_ptr<SocketState> &state) : state_(state) {
        if (!state_) {
            throw Error("socket is not open");
        }
        std::lock_guard lock(state_->mutex);
        if (state_->closing || state_->descriptor < 0) {
            throw Error("socket is closed");
        }
        ++state_->active_operations;
        descriptor_ = state_->descriptor;
    }

    ~SocketOperation() {
        if (!state_) {
            return;
        }
        std::lock_guard lock(state_->mutex);
        --state_->active_operations;
        state_->changed.notify_all();
    }

    int descriptor() const noexcept {
        return descriptor_;
    }

  private:
    std::shared_ptr<SocketState> state_;
    int descriptor_ = -1;
};

std::string socket_error(std::string_view operation) {
    return std::string(operation) + ": " +
           std::error_code(errno, std::generic_category()).message();
}

Bytes port_bytes(std::uint16_t port) {
    return {static_cast<Byte>(port >> 8U), static_cast<Byte>(port)};
}

void set_timeout(int descriptor, int option, int seconds) {
    if (seconds < 0) {
        throw Error("socket timeout cannot be negative");
    }
    timeval timeout{};
    timeout.tv_sec = seconds;
    if (setsockopt(descriptor, SOL_SOCKET, option, &timeout, sizeof(timeout)) < 0) {
        throw Error(socket_error("could not set socket timeout"));
    }
}

void socks5_connect(Socket &socket, const HostPort &target) {
    const Bytes greeting{0x05, 0x01, 0x00};
    socket.send_all(greeting);
    std::array<Byte, 2> greeting_reply{};
    if (!socket.receive_exact(greeting_reply) || greeting_reply[0] != 0x05 ||
        greeting_reply[1] != 0x00) {
        throw Error("SOCKS5 proxy refused unauthenticated negotiation");
    }
    if (target.host.size() > 255) {
        throw Error("SOCKS5 target hostname is too long");
    }
    Bytes request{0x05, 0x01, 0x00, 0x03, static_cast<Byte>(target.host.size())};
    request.insert(request.end(), target.host.begin(), target.host.end());
    const Bytes encoded_port = port_bytes(target.port);
    request.insert(request.end(), encoded_port.begin(), encoded_port.end());
    socket.send_all(request);

    std::array<Byte, 4> reply{};
    if (!socket.receive_exact(reply) || reply[0] != 0x05 || reply[1] != 0x00) {
        throw Error("SOCKS5 proxy could not connect to the peer");
    }
    std::size_t address_size = 0;
    switch (reply[3]) {
    case 0x01:
        address_size = 4;
        break;
    case 0x04:
        address_size = 16;
        break;
    case 0x03: {
        std::array<Byte, 1> length{};
        if (!socket.receive_exact(length)) {
            throw Error("truncated SOCKS5 response");
        }
        address_size = length[0];
        break;
    }
    default:
        throw Error("SOCKS5 proxy returned an unknown address type");
    }
    Bytes ignored(address_size + 2);
    if (!socket.receive_exact(ignored)) {
        throw Error("truncated SOCKS5 response");
    }
}

} // namespace

Socket::Socket(int descriptor) : state_(std::make_shared<SocketState>(descriptor)) {}

Socket::~Socket() {
    close();
}

Socket::Socket(Socket &&other) noexcept : state_(std::move(other.state_)) {}

Socket &Socket::operator=(Socket &&other) noexcept {
    if (this != &other) {
        close();
        state_ = std::move(other.state_);
    }
    return *this;
}

Socket Socket::connect_tcp(const HostPort &address) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *results = nullptr;
    const std::string port = std::to_string(address.port);
    const int lookup = getaddrinfo(address.host.c_str(), port.c_str(), &hints, &results);
    if (lookup != 0) {
        throw Error("could not resolve peer address: " + std::string(gai_strerror(lookup)));
    }

    int descriptor = -1;
    int last_error = 0;
    for (addrinfo *candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
        descriptor = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (descriptor < 0) {
            last_error = errno;
            continue;
        }
        const int original_flags = fcntl(descriptor, F_GETFL, 0);
        if (original_flags < 0 || fcntl(descriptor, F_SETFL, original_flags | O_NONBLOCK) < 0) {
            last_error = errno;
            ::close(descriptor);
            descriptor = -1;
            continue;
        }
        int connect_result = ::connect(descriptor, candidate->ai_addr, candidate->ai_addrlen);
        if (connect_result < 0 && errno == EINPROGRESS) {
            pollfd wait{descriptor, POLLOUT, 0};
            connect_result = ::poll(&wait, 1, 10'000);
            if (connect_result > 0) {
                socklen_t error_size = sizeof(last_error);
                if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &last_error, &error_size) < 0) {
                    last_error = errno;
                }
                connect_result = last_error == 0 ? 0 : -1;
            } else {
                last_error = connect_result == 0 ? ETIMEDOUT : errno;
                connect_result = -1;
            }
        } else if (connect_result < 0) {
            last_error = errno;
        }
        if (connect_result == 0) {
            if (fcntl(descriptor, F_SETFL, original_flags) == 0) {
                break;
            }
            last_error = errno;
        }
        ::close(descriptor);
        descriptor = -1;
    }
    freeaddrinfo(results);
    if (descriptor < 0) {
        errno = last_error;
        throw Error(socket_error("could not connect to peer"));
    }
    return Socket(descriptor);
}

Socket Socket::connect_peer(const PeerEndpoint &endpoint) {
    if (endpoint.transport == PeerTransport::direct_tcp) {
        return connect_tcp(endpoint.target);
    }
    if (!endpoint.proxy) {
        throw Error("SOCKS5 endpoint has no proxy address");
    }
    Socket socket = connect_tcp(*endpoint.proxy);
    socket.set_receive_timeout(10);
    socket.set_send_timeout(10);
    try {
        socks5_connect(socket, endpoint.target);
        socket.set_receive_timeout(0);
    } catch (...) {
        socket.close();
        throw;
    }
    return socket;
}

Socket Socket::listen_tcp(const HostPort &address, int backlog) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    addrinfo *results = nullptr;
    const std::string port = std::to_string(address.port);
    const char *host = address.host == "*" ? nullptr : address.host.c_str();
    const int lookup = getaddrinfo(host, port.c_str(), &hints, &results);
    if (lookup != 0) {
        throw Error("could not resolve listen address: " + std::string(gai_strerror(lookup)));
    }

    int descriptor = -1;
    int last_error = 0;
    for (addrinfo *candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
        descriptor = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (descriptor < 0) {
            last_error = errno;
            continue;
        }
        const int enabled = 1;
        setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
        if (::bind(descriptor, candidate->ai_addr, candidate->ai_addrlen) == 0 &&
            ::listen(descriptor, backlog) == 0) {
            break;
        }
        last_error = errno;
        ::close(descriptor);
        descriptor = -1;
    }
    freeaddrinfo(results);
    if (descriptor < 0) {
        errno = last_error;
        throw Error(socket_error("could not listen"));
    }
    return Socket(descriptor);
}

Socket Socket::accept() const {
    for (;;) {
        auto accepted =
            accept_until(std::chrono::steady_clock::now() + std::chrono::milliseconds(250));
        if (accepted) {
            return std::move(*accepted);
        }
    }
}

std::optional<Socket> Socket::accept_until(std::chrono::steady_clock::time_point deadline) const {
    for (;;) {
        SocketOperation operation(state_);
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return std::nullopt;
        }
        auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        remaining = std::clamp<std::int64_t>(remaining, 1, std::numeric_limits<int>::max());
        pollfd wait{operation.descriptor(), POLLIN, 0};
        const int ready = ::poll(&wait, 1, static_cast<int>(remaining));
        if (ready == 0) {
            return std::nullopt;
        }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw Error(socket_error("could not wait for connection"));
        }
        const int descriptor = ::accept(operation.descriptor(), nullptr, nullptr);
        if (descriptor >= 0) {
            return Socket(descriptor);
        }
        if (errno != EINTR) {
            throw Error(socket_error("could not accept connection"));
        }
    }
}

std::optional<std::string> Socket::peer_rate_key() const {
    SocketOperation operation(state_);
    sockaddr_storage address{};
    socklen_t address_size = sizeof(address);
    if (::getpeername(operation.descriptor(), reinterpret_cast<sockaddr *>(&address),
                      &address_size) < 0) {
        throw Error(socket_error("could not inspect peer address"));
    }
    std::string key;
    if (address.ss_family == AF_INET) {
        const auto &ipv4 = reinterpret_cast<const sockaddr_in &>(address).sin_addr;
        const auto *bytes = reinterpret_cast<const Byte *>(&ipv4);
        if (bytes[0] == 127) {
            return std::nullopt;
        }
        key.assign("4", 1);
        key.append(reinterpret_cast<const char *>(bytes), sizeof(ipv4));
        return key;
    }
    if (address.ss_family == AF_INET6) {
        const auto &ipv6 = reinterpret_cast<const sockaddr_in6 &>(address).sin6_addr;
        if (IN6_IS_ADDR_LOOPBACK(&ipv6)) {
            return std::nullopt;
        }
        if (IN6_IS_ADDR_V4MAPPED(&ipv6)) {
            if (ipv6.s6_addr[12] == 127) {
                return std::nullopt;
            }
            key.assign("4", 1);
            key.append(reinterpret_cast<const char *>(&ipv6.s6_addr[12]), 4);
            return key;
        }
        // Rate-limit IPv6 by /64 so rotating interface addresses does not
        // trivially bypass the admission bound.
        key.assign("6", 1);
        key.append(reinterpret_cast<const char *>(ipv6.s6_addr), 8);
        return key;
    }
    throw Error("peer address has an unsupported family");
}

void Socket::send_all(std::span<const Byte> data) const {
    SocketOperation operation(state_);
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t written = ::send(operation.descriptor(), data.data() + offset,
                                       data.size() - offset, MSG_NOSIGNAL);
        if (written > 0) {
            offset += static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        throw Error(socket_error("socket write failed"));
    }
}

void Socket::send_all_until(std::span<const Byte> data,
                            std::chrono::steady_clock::time_point deadline) const {
    SocketOperation operation(state_);
    std::size_t offset = 0;
    while (offset < data.size()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw Error("socket write deadline exceeded");
        }
        auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        remaining = std::clamp<std::int64_t>(remaining, 1, std::numeric_limits<int>::max());
        pollfd wait{operation.descriptor(), POLLOUT, 0};
        const int ready = ::poll(&wait, 1, static_cast<int>(remaining));
        if (ready == 0) {
            throw Error("socket write deadline exceeded");
        }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw Error(socket_error("could not wait for socket write"));
        }
        const ssize_t written = ::send(operation.descriptor(), data.data() + offset,
                                       data.size() - offset, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (written > 0) {
            offset += static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        throw Error(socket_error("socket write failed"));
    }
}

std::optional<std::size_t> Socket::send_some(std::span<const Byte> data) const {
    if (data.empty()) {
        return std::size_t{0};
    }
    SocketOperation operation(state_);
    for (;;) {
        const ssize_t written =
            ::send(operation.descriptor(), data.data(), data.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (written >= 0) {
            return static_cast<std::size_t>(written);
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return std::nullopt;
        }
        throw Error(socket_error("socket write failed"));
    }
}

bool Socket::receive_exact(std::span<Byte> output) const {
    SocketOperation operation(state_);
    std::size_t offset = 0;
    while (offset < output.size()) {
        const ssize_t received =
            ::recv(operation.descriptor(), output.data() + offset, output.size() - offset, 0);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received == 0) {
            return false;
        }
        if (errno == EINTR) {
            continue;
        }
        throw Error(socket_error("socket read failed"));
    }
    return true;
}

bool Socket::receive_exact_until(std::span<Byte> output,
                                 std::chrono::steady_clock::time_point deadline) const {
    SocketOperation operation(state_);
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw Error("socket read deadline exceeded");
        }
        auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        remaining = std::clamp<std::int64_t>(remaining, 1, std::numeric_limits<int>::max());
        pollfd wait{operation.descriptor(), POLLIN, 0};
        const int ready = ::poll(&wait, 1, static_cast<int>(remaining));
        if (ready == 0) {
            throw Error("socket read deadline exceeded");
        }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw Error(socket_error("could not wait for socket read"));
        }
        const ssize_t received = ::recv(operation.descriptor(), output.data() + offset,
                                        output.size() - offset, MSG_DONTWAIT);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received == 0) {
            return false;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        }
        throw Error(socket_error("socket read failed"));
    }
    return true;
}

std::optional<std::size_t> Socket::receive_some(std::span<Byte> output) const {
    if (output.empty()) {
        return std::size_t{0};
    }
    SocketOperation operation(state_);
    for (;;) {
        const ssize_t received =
            ::recv(operation.descriptor(), output.data(), output.size(), MSG_DONTWAIT);
        if (received >= 0) {
            return static_cast<std::size_t>(received);
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return std::nullopt;
        }
        throw Error(socket_error("socket read failed"));
    }
}

std::optional<std::string> Socket::receive_line(std::size_t maximum) const {
    std::string line;
    line.reserve(std::min<std::size_t>(maximum, 512));
    for (;;) {
        Byte byte = 0;
        if (!receive_exact(std::span<Byte>(&byte, 1))) {
            return std::nullopt;
        }
        if (byte == '\n') {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            return line;
        }
        if (line.size() >= maximum) {
            throw Error("line exceeds protocol limit");
        }
        line.push_back(static_cast<char>(byte));
    }
}

void Socket::set_send_timeout(int seconds) const {
    SocketOperation operation(state_);
    set_timeout(operation.descriptor(), SO_SNDTIMEO, seconds);
}

void Socket::set_receive_timeout(int seconds) const {
    SocketOperation operation(state_);
    set_timeout(operation.descriptor(), SO_RCVTIMEO, seconds);
}

bool Socket::valid() const {
    if (!state_) {
        return false;
    }
    std::lock_guard lock(state_->mutex);
    return !state_->closing && state_->descriptor >= 0;
}

void Socket::close() noexcept {
    const auto state = state_;
    if (!state) {
        return;
    }
    int descriptor = -1;
    {
        std::unique_lock lock(state->mutex);
        if (state->closing) {
            state->changed.wait(lock, [&state] { return state->descriptor < 0; });
            return;
        }
        state->closing = true;
        descriptor = state->descriptor;
    }
    if (descriptor >= 0) {
        ::shutdown(descriptor, SHUT_RDWR);
    }
    {
        std::unique_lock lock(state->mutex);
        state->changed.wait(lock, [&state] { return state->active_operations == 0; });
        descriptor = state->descriptor;
        state->descriptor = -1;
        state->changed.notify_all();
    }
    if (descriptor >= 0) {
        ::close(descriptor);
    }
}

} // namespace kairc
