#include "kairc/p2p.hpp"

#include "kairc/codec.hpp"
#include "kairc/crypto.hpp"
#include "kairc/node.hpp"
#include "kairc/socket.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <limits>
#include <mutex>
#include <thread>

namespace kairc {

namespace {

constexpr std::array<Byte, 8> kProtocolMagic{'K', 'A', 'I', 'R', 'C', 'P', '2', 'P'};
constexpr std::uint16_t kProtocolVersion = 1;
constexpr std::size_t kMaximumFrame = 1024ULL * 1024ULL;
constexpr std::size_t kInventoryLimit = 256;
constexpr std::size_t kMaximumPeerSessions = 64;

enum class FrameType : std::uint8_t {
    inventory = 1,
    get_events = 2,
    event = 3,
    ping = 4,
    pong = 5,
};

struct SessionSecret {
    std::array<Byte, crypto_kx_SECRETKEYBYTES> bytes{};
    ~SessionSecret() {
        crypto::wipe(bytes);
    }
};

Nonce counter_nonce(std::uint64_t counter) {
    Nonce nonce{};
    for (std::size_t index = 0; index < 8; ++index) {
        nonce[nonce.size() - 1 - index] = static_cast<Byte>(counter >> (index * 8));
    }
    return nonce;
}

Bytes encode_ids(std::span<const Hash> ids) {
    if (ids.size() > kInventoryLimit) {
        throw Error("peer ID list exceeds protocol limit");
    }
    Writer writer;
    writer.u16(static_cast<std::uint16_t>(ids.size()));
    for (const Hash &id : ids) {
        writer.fixed(id);
    }
    return std::move(writer).take();
}

std::vector<Hash> decode_ids(std::span<const Byte> payload) {
    Reader reader(payload);
    const std::size_t count = reader.u16();
    if (count > kInventoryLimit) {
        throw Error("peer ID list exceeds protocol limit");
    }
    std::vector<Hash> ids;
    ids.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        ids.push_back(reader.fixed<32>("event ID"));
    }
    if (!reader.empty()) {
        throw Error("peer ID list has trailing bytes");
    }
    return ids;
}

class Link {
  public:
    Link(Socket socket, Hash network, bool client)
        : socket_(std::move(socket)), network_(network), client_(client) {}

    ~Link() {
        close();
        sodium_memzero(rx_key_.data(), rx_key_.size());
        sodium_memzero(tx_key_.data(), tx_key_.size());
    }

    void establish() {
        crypto::initialize();
        socket_.set_send_timeout(10);
        socket_.set_receive_timeout(10);
        std::array<Byte, crypto_kx_PUBLICKEYBYTES> public_key{};
        SessionSecret secret_key;
        crypto_kx_keypair(public_key.data(), secret_key.bytes.data());

        Writer hello;
        hello.raw(kProtocolMagic);
        hello.u16(kProtocolVersion);
        hello.fixed(network_);
        hello.fixed(public_key);
        const Bytes ours = std::move(hello).take();
        socket_.send_all(ours);

        Bytes theirs(ours.size());
        if (!socket_.receive_exact(theirs)) {
            throw Error("peer closed during handshake");
        }
        Reader reader(theirs);
        const auto magic = reader.raw(kProtocolMagic.size());
        if (!std::equal(magic.begin(), magic.end(), kProtocolMagic.begin())) {
            throw Error("peer has an invalid protocol magic");
        }
        if (reader.u16() != kProtocolVersion) {
            throw Error("peer uses an incompatible protocol version");
        }
        if (reader.fixed<32>("peer network") != network_) {
            throw Error("peer belongs to another Kairc network");
        }
        const auto peer_key = reader.fixed<crypto_kx_PUBLICKEYBYTES>("peer session key");
        if (!reader.empty()) {
            throw Error("peer handshake has trailing bytes");
        }

        int result = -1;
        if (client_) {
            result =
                crypto_kx_client_session_keys(rx_key_.data(), tx_key_.data(), public_key.data(),
                                              secret_key.bytes.data(), peer_key.data());
        } else {
            result =
                crypto_kx_server_session_keys(rx_key_.data(), tx_key_.data(), public_key.data(),
                                              secret_key.bytes.data(), peer_key.data());
        }
        if (result != 0) {
            throw Error("peer supplied an invalid X25519 session key");
        }
        socket_.set_receive_timeout(0);
        ready_.store(true);
    }

    void send(FrameType type, std::span<const Byte> payload = {}) {
        std::lock_guard lock(write_mutex_);
        if (!ready_.load()) {
            throw Error("peer link is not ready");
        }
        Writer plaintext_writer;
        plaintext_writer.u8(static_cast<std::uint8_t>(type));
        plaintext_writer.raw(payload);
        const Bytes plaintext = std::move(plaintext_writer).take();
        const std::size_t encrypted_size =
            plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        if (encrypted_size > kMaximumFrame) {
            throw Error("outbound peer frame exceeds protocol limit");
        }
        Writer header_writer;
        header_writer.u32(static_cast<std::uint32_t>(encrypted_size));
        const Bytes header = std::move(header_writer).take();
        if (tx_counter_ == std::numeric_limits<std::uint64_t>::max()) {
            throw Error("peer frame nonce space exhausted");
        }
        const Nonce nonce = counter_nonce(tx_counter_++);
        const Bytes ciphertext = crypto::encrypt(tx_key_, nonce, plaintext, header);
        socket_.send_all(header);
        socket_.send_all(ciphertext);
    }

    std::pair<FrameType, Bytes> receive() {
        std::array<Byte, 4> header{};
        if (!socket_.receive_exact(header)) {
            throw Error("peer closed the connection");
        }
        Reader header_reader(header);
        const std::size_t size = header_reader.u32();
        if (size < crypto_aead_xchacha20poly1305_ietf_ABYTES + 1 || size > kMaximumFrame) {
            throw Error("peer frame has an invalid length");
        }
        Bytes ciphertext(size);
        if (!socket_.receive_exact(ciphertext)) {
            throw Error("peer closed during a frame");
        }
        if (rx_counter_ == std::numeric_limits<std::uint64_t>::max()) {
            throw Error("peer frame nonce space exhausted");
        }
        const Nonce nonce = counter_nonce(rx_counter_++);
        const auto plaintext = crypto::decrypt(rx_key_, nonce, ciphertext, header);
        if (!plaintext || plaintext->empty()) {
            throw Error("peer frame authentication failed");
        }
        const auto type = static_cast<FrameType>(plaintext->front());
        return {type, Bytes(plaintext->begin() + 1, plaintext->end())};
    }

    void close() noexcept {
        socket_.close();
    }
    bool ready() const noexcept {
        return ready_.load();
    }

  private:
    Socket socket_;
    Hash network_{};
    bool client_ = false;
    Key rx_key_{};
    Key tx_key_{};
    std::uint64_t rx_counter_ = 0;
    std::uint64_t tx_counter_ = 0;
    std::atomic<bool> ready_{false};
    std::mutex write_mutex_;
};

} // namespace

class PeerNetwork::Impl {
  public:
    Impl(Node &node, std::optional<HostPort> listen, std::vector<PeerEndpoint> peers)
        : node_(node), listen_address_(std::move(listen)), peers_(std::move(peers)) {}

    ~Impl() {
        stop();
    }

    void start() {
        if (running_.exchange(true)) {
            return;
        }
        try {
            if (listen_address_) {
                listener_ = Socket::listen_tcp(*listen_address_);
                accept_thread_ = std::thread([this] { accept_loop(); });
            }
            for (const PeerEndpoint &endpoint : peers_) {
                connector_threads_.emplace_back([this, endpoint] { connector_loop(endpoint); });
            }
        } catch (...) {
            stop();
            throw;
        }
    }

    void stop() {
        if (!running_.exchange(false)) {
            return;
        }
        listener_.close();
        {
            std::lock_guard lock(links_mutex_);
            for (const auto &link : links_) {
                link->close();
            }
        }
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
        for (std::thread &connector : connector_threads_) {
            if (connector.joinable()) {
                connector.join();
            }
        }
        connector_threads_.clear();

        {
            std::unique_lock lock(sessions_mutex_);
            sessions_changed_.wait(lock, [this] { return active_sessions_.load() == 0; });
        }
        {
            std::lock_guard lock(links_mutex_);
            links_.clear();
        }
    }

    void broadcast(const Event &event) {
        broadcast_except(event, nullptr);
    }

    std::size_t connected_peers() const {
        std::lock_guard lock(links_mutex_);
        return static_cast<std::size_t>(std::count_if(
            links_.begin(), links_.end(), [](const auto &link) { return link->ready(); }));
    }

  private:
    void accept_loop() {
        while (running_.load()) {
            try {
                Socket socket = listener_.accept();
                if (!running_.load()) {
                    socket.close();
                    break;
                }
                if (!reserve_session()) {
                    socket.close();
                    continue;
                }
                try {
                    std::thread([this, socket = std::move(socket)]() mutable {
                        run_reserved_link(std::move(socket), false);
                    }).detach();
                } catch (...) {
                    release_session();
                    throw;
                }
            } catch (const std::exception &) {
                if (running_.load()) {
                    std::cerr << "kaircd: inbound P2P accept failed\n";
                }
            }
        }
    }

    void connector_loop(const PeerEndpoint &endpoint) {
        while (running_.load()) {
            try {
                Socket socket = Socket::connect_peer(endpoint);
                if (!running_.load()) {
                    socket.close();
                    break;
                }
                if (reserve_session()) {
                    run_reserved_link(std::move(socket), true);
                }
            } catch (const std::exception &) {
                if (running_.load()) {
                    std::cerr << "kaircd: outbound P2P connection unavailable; retrying\n";
                }
            }
            for (int tenth = 0; tenth < 30 && running_.load(); ++tenth) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

    bool reserve_session() {
        std::size_t current = active_sessions_.load();
        while (current < kMaximumPeerSessions) {
            if (active_sessions_.compare_exchange_weak(current, current + 1)) {
                return true;
            }
        }
        return false;
    }

    void release_session() {
        std::lock_guard lock(sessions_mutex_);
        active_sessions_.fetch_sub(1);
        sessions_changed_.notify_all();
    }

    void run_reserved_link(Socket socket, bool client) {
        struct SessionGuard {
            Impl *owner;
            ~SessionGuard() {
                owner->release_session();
            }
        } guard{this};
        std::shared_ptr<Link> link;
        try {
            if (!running_.load()) {
                return;
            }
            link = std::make_shared<Link>(std::move(socket), node_.network(), client);
            {
                std::lock_guard lock(links_mutex_);
                if (!running_.load()) {
                    link->close();
                    return;
                }
                links_.push_back(link);
            }
            link->establish();
            const std::vector<Hash> inventory = node_.recent_ids(kInventoryLimit);
            link->send(FrameType::inventory, encode_ids(inventory));
            while (running_.load()) {
                auto [type, payload] = link->receive();
                handle_frame(link, type, payload);
            }
        } catch (...) {
            // Peer addresses and free-form errors are deliberately not logged by default.
            if (link) {
                link->close();
            }
        }
        if (link) {
            link->close();
            std::lock_guard lock(links_mutex_);
            std::erase(links_, link);
        }
    }

    void handle_frame(const std::shared_ptr<Link> &link, FrameType type,
                      std::span<const Byte> payload) {
        switch (type) {
        case FrameType::inventory: {
            std::vector<Hash> wanted;
            for (const Hash &id : decode_ids(payload)) {
                if (!node_.load(id)) {
                    wanted.push_back(id);
                }
            }
            if (!wanted.empty()) {
                link->send(FrameType::get_events, encode_ids(wanted));
            }
            break;
        }
        case FrameType::get_events:
            for (const Hash &id : decode_ids(payload)) {
                if (const auto event = node_.load(id)) {
                    link->send(FrameType::event, event->serialize());
                }
            }
            break;
        case FrameType::event: {
            Event event = Event::deserialize(payload);
            IngestResult result = node_.ingest(std::move(event));
            if (result.status == IngestStatus::pending_parents && !result.missing.empty()) {
                const std::size_t count = std::min(result.missing.size(), kInventoryLimit);
                link->send(FrameType::get_events,
                           encode_ids(std::span<const Hash>(result.missing).first(count)));
            }
            if (result.status == IngestStatus::accepted) {
                for (const Event &accepted : result.accepted) {
                    broadcast_except(accepted, link.get());
                }
            }
            break;
        }
        case FrameType::ping:
            link->send(FrameType::pong);
            break;
        case FrameType::pong:
            break;
        default:
            throw Error("peer sent an unknown frame type");
        }
    }

    void broadcast_except(const Event &event, const Link *excluded) {
        const Bytes wire = event.serialize();
        std::vector<std::shared_ptr<Link>> links;
        {
            std::lock_guard lock(links_mutex_);
            links = links_;
        }
        for (const auto &link : links) {
            if (link.get() == excluded || !link->ready()) {
                continue;
            }
            try {
                link->send(FrameType::event, wire);
            } catch (const Error &) {
                link->close();
            }
        }
    }

    Node &node_;
    std::optional<HostPort> listen_address_;
    std::vector<PeerEndpoint> peers_;
    std::atomic<bool> running_{false};
    Socket listener_;
    std::thread accept_thread_;
    std::vector<std::thread> connector_threads_;
    std::atomic<std::size_t> active_sessions_{0};
    std::mutex sessions_mutex_;
    std::condition_variable sessions_changed_;
    mutable std::mutex links_mutex_;
    std::vector<std::shared_ptr<Link>> links_;
};

PeerNetwork::PeerNetwork(Node &node, std::optional<HostPort> listen,
                         std::vector<PeerEndpoint> peers)
    : impl_(std::make_unique<Impl>(node, std::move(listen), std::move(peers))) {}

PeerNetwork::~PeerNetwork() = default;

void PeerNetwork::start() {
    impl_->start();
}
void PeerNetwork::stop() {
    impl_->stop();
}
void PeerNetwork::broadcast(const Event &event) {
    impl_->broadcast(event);
}
std::size_t PeerNetwork::connected_peers() const {
    return impl_->connected_peers();
}

} // namespace kairc
