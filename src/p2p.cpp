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
#include <functional>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <semaphore>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace kairc {

namespace {

constexpr std::array<Byte, 8> kProtocolMagic{'K', 'A', 'I', 'R', 'C', 'P', '3', 'P'};
constexpr std::array<Byte, 8> kCookieMagic{'K', 'A', 'I', 'R', 'C', 'C', 'K', '3'};
constexpr std::uint16_t kProtocolVersion = 3;
constexpr std::size_t kMaximumFrame = 1024ULL * 1024ULL;
constexpr std::size_t kInventoryLimit = 256;
constexpr std::size_t kMaximumPeerSessions = 64;
constexpr std::size_t kMaximumInboundSessions = 48;
constexpr std::size_t kMaximumInboundHandshakes = 16;
constexpr std::size_t kMaximumInboundHandshakesPerIdentity = 2;
constexpr std::size_t kMaximumPendingHellos = 256;
constexpr std::size_t kMaximumPendingHellosPerSource = 2;
constexpr std::size_t kMaximumAcceptBatch = 64;
constexpr std::size_t kMaximumSessionsPerIdentity = 4;
constexpr std::size_t kMaximumUnknownIdentityBudgets = 1'024;
constexpr std::size_t kDiscoveryResponseLimit = 8;
constexpr std::size_t kMaximumOutstandingDiscoveryRequests = 4;
constexpr std::size_t kDiscoveryWorkerCount = 4;
constexpr std::size_t kMaximumDiscoverySessions = 16;
constexpr std::size_t kMaximumUntrustedDiscoverySessions = 12;
constexpr std::size_t kMaximumDiscoveryBackoffEntries = 4'096;
constexpr std::size_t kPeerHelloSize = 8 + 2 + 32 + 1 + 32 + crypto_kx_PUBLICKEYBYTES + 32 + 64;
constexpr std::size_t kCookiePreludeSize = 8 + 2 + 32 + 32;
constexpr auto kBudgetWindow = std::chrono::minutes(1);
constexpr auto kHandshakeDeadline = std::chrono::seconds(10);
constexpr auto kInboundHelloDeadline = std::chrono::seconds(3);
constexpr auto kFrameWriteDeadline = std::chrono::seconds(30);
constexpr auto kFrameReadDeadline = std::chrono::seconds(30);
constexpr auto kDiscoveryRequestDeadline = std::chrono::seconds(30);
constexpr auto kDiscoveryRetryDelay = std::chrono::seconds(30);
constexpr auto kDiscoverySuccessfulRetryDelay = std::chrono::minutes(10);
constexpr auto kDiscoverySessionLifetime = std::chrono::minutes(5);
constexpr auto kDiscoveryBackoffRetention =
    std::chrono::seconds(kPeerRecordMaximumLifetimeSeconds + kPeerRecordFutureSkewSeconds);
constexpr Byte kClientRole = 1;
constexpr Byte kServerRole = 2;

std::uint64_t unix_time_seconds() {
    return unix_time_ms() / 1'000ULL;
}

enum class FrameType : std::uint8_t {
    inventory = 1,
    get_events = 2,
    event = 3,
    ping = 4,
    pong = 5,
    peer_record = 6,
    find_nodes = 7,
    nodes = 8,
};

enum class SessionReservation : std::uint8_t {
    inbound_handshake,
    inbound_session,
    outbound_session,
    trusted_discovery_session,
    untrusted_discovery_session,
};

struct SessionSecret {
    std::array<Byte, crypto_kx_SECRETKEYBYTES> bytes{};
    ~SessionSecret() {
        crypto::wipe(bytes);
    }
};

class TokenBucket {
  public:
    explicit TokenBucket(std::uint64_t capacity)
        : capacity_(static_cast<long double>(capacity)), tokens_(capacity_),
          updated_(Clock::now()) {}

    bool consume(std::uint64_t amount) {
        if (!can_consume(amount)) {
            return false;
        }
        debit(amount);
        return true;
    }

    bool can_consume(std::uint64_t amount) {
        const auto now = Clock::now();
        const auto elapsed = now - updated_;
        updated_ = now;
        const long double elapsed_fraction =
            static_cast<long double>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count()) /
            static_cast<long double>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(kBudgetWindow).count());
        tokens_ = std::min(capacity_, tokens_ + elapsed_fraction * capacity_);
        const long double requested = static_cast<long double>(amount);
        return requested <= tokens_;
    }

    void debit(std::uint64_t amount) {
        tokens_ -= static_cast<long double>(amount);
    }

  private:
    using Clock = std::chrono::steady_clock;
    long double capacity_ = 0;
    long double tokens_ = 0;
    Clock::time_point updated_;
};

class TrafficBudget {
  public:
    TrafficBudget(std::uint64_t bytes, std::uint64_t frames, std::uint64_t events)
        : bytes_(bytes), frames_(frames), events_(events) {}

    bool consume_frame_with(TrafficBudget &global, std::size_t bytes) {
        if (this == &global) {
            std::lock_guard lock(mutex_);
            return consume_frame_locked(bytes);
        }
        std::scoped_lock lock(mutex_, global.mutex_);
        const auto amount = static_cast<std::uint64_t>(bytes);
        if (!frames_.can_consume(1) || !bytes_.can_consume(amount) ||
            !global.frames_.can_consume(1) || !global.bytes_.can_consume(amount)) {
            return false;
        }
        frames_.debit(1);
        bytes_.debit(amount);
        global.frames_.debit(1);
        global.bytes_.debit(amount);
        return true;
    }

    bool consume_events_with(TrafficBudget &global, std::size_t count) {
        if (count == 0) {
            return true;
        }
        const auto amount = static_cast<std::uint64_t>(count);
        if (this == &global) {
            std::lock_guard lock(mutex_);
            return events_.consume(amount);
        }
        std::scoped_lock lock(mutex_, global.mutex_);
        if (!events_.can_consume(amount) || !global.events_.can_consume(amount)) {
            return false;
        }
        events_.debit(amount);
        global.events_.debit(amount);
        return true;
    }

  private:
    bool consume_frame_locked(std::size_t bytes) {
        const auto amount = static_cast<std::uint64_t>(bytes);
        if (!frames_.can_consume(1) || !bytes_.can_consume(amount)) {
            return false;
        }
        frames_.debit(1);
        bytes_.debit(amount);
        return true;
    }

    std::mutex mutex_;
    TokenBucket bytes_;
    TokenBucket frames_;
    TokenBucket events_;
};

std::size_t cryptographic_items(FrameType type, std::span<const Byte> payload) {
    if (type == FrameType::event || type == FrameType::peer_record) {
        return 1;
    }
    if (type == FrameType::nodes) {
        if (payload.size() < 9) {
            throw Error("peer NODES frame is truncated");
        }
        const std::size_t count = payload[8];
        if (count > kDiscoveryResponseLimit) {
            throw Error("peer NODES frame exceeds its record limit");
        }
        return count;
    }
    return 0;
}

class HandshakeBudget {
  public:
    explicit HandshakeBudget(std::uint64_t authenticated_handshakes_per_minute)
        : handshakes_(authenticated_handshakes_per_minute) {}

    bool consume() {
        std::lock_guard lock(mutex_);
        return handshakes_.consume(1);
    }

    bool consume_with(HandshakeBudget &global) {
        if (this == &global) {
            return consume();
        }
        std::scoped_lock lock(mutex_, global.mutex_);
        if (!handshakes_.can_consume(1) || !global.handshakes_.can_consume(1)) {
            return false;
        }
        handshakes_.debit(1);
        global.handshakes_.debit(1);
        return true;
    }

  private:
    std::mutex mutex_;
    TokenBucket handshakes_;
};

Nonce counter_nonce(std::uint64_t counter) {
    Nonce nonce{};
    for (std::size_t index = 0; index < 8; ++index) {
        nonce[nonce.size() - 1 - index] = static_cast<Byte>(counter >> (index * 8));
    }
    return nonce;
}

Bytes peer_hello(const Hash &network, Byte role, const PublicKey &identity,
                 std::span<const Byte> session_key, const Key &challenge) {
    Writer writer;
    writer.raw(kProtocolMagic);
    writer.u16(kProtocolVersion);
    writer.fixed(network);
    writer.u8(role);
    writer.fixed(identity);
    writer.raw(session_key);
    writer.fixed(challenge);
    return std::move(writer).take();
}

Bytes cookie_prelude(const Hash &network, const Key &cookie) {
    Writer writer;
    writer.raw(kCookieMagic);
    writer.u16(kProtocolVersion);
    writer.fixed(network);
    writer.fixed(cookie);
    return std::move(writer).take();
}

Key decode_cookie_prelude(std::span<const Byte> prelude, const Hash &network) {
    if (prelude.size() != kCookiePreludeSize) {
        throw Error("peer cookie prelude has an invalid length");
    }
    Reader reader(prelude);
    const auto magic = reader.raw(kCookieMagic.size());
    if (!std::equal(magic.begin(), magic.end(), kCookieMagic.begin()) ||
        reader.u16() != kProtocolVersion || reader.fixed<32>("peer cookie network") != network) {
        throw Error("peer cookie prelude is invalid");
    }
    const Key cookie = reader.fixed<32>("peer cookie");
    if (!reader.empty()) {
        throw Error("peer cookie prelude has trailing bytes");
    }
    return cookie;
}

Hash peer_hello_digest(std::span<const Byte> hello) {
    return crypto::hash("kairc/peer-hello/v2", hello);
}

PublicKey precheck_client_hello(std::span<const Byte> hello, const Key &expected_cookie,
                                const Hash &network, const PublicKey &local_identity,
                                const std::vector<PublicKey> &trusted_peer_keys,
                                bool allow_unknown) {
    if (hello.size() != kPeerHelloSize) {
        throw Error("peer hello has an invalid length");
    }
    Reader reader(hello);
    const auto magic = reader.raw(kProtocolMagic.size());
    if (!std::equal(magic.begin(), magic.end(), kProtocolMagic.begin()) ||
        reader.u16() != kProtocolVersion || reader.fixed<32>("peer network") != network ||
        reader.u8() != kClientRole) {
        throw Error("peer hello precheck failed");
    }
    const PublicKey claimed_identity = reader.fixed<32>("peer identity key");
    if (claimed_identity == local_identity) {
        throw Error("peer attempted to use the local node identity");
    }
    static_cast<void>(reader.fixed<crypto_kx_PUBLICKEYBYTES>("peer session key"));
    const Key cookie = reader.fixed<32>("peer cookie");
    if (sodium_memcmp(cookie.data(), expected_cookie.data(), cookie.size()) != 0) {
        throw Error("peer hello has an invalid responder cookie");
    }
    const bool trusted = std::find(trusted_peer_keys.begin(), trusted_peer_keys.end(),
                                   claimed_identity) != trusted_peer_keys.end();
    if (!allow_unknown && !trusted) {
        throw Error("peer identity is not in the configured allowlist");
    }
    return claimed_identity;
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
    std::unordered_set<Hash, HashHasher> unique;
    ids.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        Hash id = reader.fixed<32>("event ID");
        if (!unique.insert(id).second) {
            throw Error("peer ID list contains a duplicate");
        }
        ids.push_back(id);
    }
    if (!reader.empty()) {
        throw Error("peer ID list has trailing bytes");
    }
    return ids;
}

Bytes encode_find_nodes(std::uint64_t request_id, const Hash &target) {
    if (request_id == 0) {
        throw Error("discovery request ID must be non-zero");
    }
    Writer writer;
    writer.u64(request_id);
    writer.fixed(target);
    return std::move(writer).take();
}

std::pair<std::uint64_t, Hash> decode_find_nodes(std::span<const Byte> payload) {
    Reader reader(payload);
    const std::uint64_t request_id = reader.u64();
    const Hash target = reader.fixed<32>("discovery target");
    if (request_id == 0 || !reader.empty()) {
        throw Error("peer FIND_NODES frame is invalid");
    }
    return {request_id, target};
}

Bytes encode_peer_records(std::uint64_t request_id, std::span<const PeerRecord> records) {
    if (request_id == 0 || records.size() > kDiscoveryResponseLimit) {
        throw Error("discovery response exceeds its record limit");
    }
    Writer writer;
    writer.u64(request_id);
    writer.u8(static_cast<std::uint8_t>(records.size()));
    for (const PeerRecord &record : records) {
        writer.bytes(record.serialize());
    }
    return std::move(writer).take();
}

std::pair<std::uint64_t, std::vector<PeerRecord>>
decode_peer_records(std::span<const Byte> payload) {
    Reader reader(payload);
    const std::uint64_t request_id = reader.u64();
    const std::size_t count = reader.u8();
    if (request_id == 0 || count > kDiscoveryResponseLimit) {
        throw Error("peer NODES frame exceeds its record limit");
    }
    std::vector<PeerRecord> records;
    records.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        records.push_back(PeerRecord::deserialize(reader.bytes(kMaximumPeerRecordSize)));
    }
    if (!reader.empty()) {
        throw Error("peer NODES frame has trailing bytes");
    }
    return {request_id, std::move(records)};
}

class Link {
  public:
    Link(Socket socket, Hash network, bool client, const PeerLimits &limits,
         std::shared_ptr<TrafficBudget> global_ingress,
         std::shared_ptr<TrafficBudget> global_egress,
         std::shared_ptr<HandshakeBudget> global_handshake_budget, const crypto::Identity &identity,
         const std::vector<PublicKey> &trusted_peer_keys, bool allow_unknown,
         std::optional<PublicKey> expected_identity = std::nullopt,
         std::optional<std::chrono::steady_clock::time_point> hard_deadline = std::nullopt)
        : socket_(std::move(socket)), network_(network), client_(client),
          idle_timeout_seconds_(limits.idle_timeout_seconds),
          global_ingress_(std::move(global_ingress)), global_egress_(std::move(global_egress)),
          global_handshake_budget_(std::move(global_handshake_budget)), identity_(identity),
          trusted_peer_keys_(trusted_peer_keys), allow_unknown_(allow_unknown),
          expected_identity_(expected_identity), hard_deadline_(hard_deadline) {}

    ~Link() {
        close();
        sodium_memzero(rx_key_.data(), rx_key_.size());
        sodium_memzero(tx_key_.data(), tx_key_.size());
    }

    void establish(std::span<const Byte> prefetched_hello = {},
                   const std::optional<Key> &expected_cookie = std::nullopt,
                   const std::function<void(const PublicKey &, bool)> &on_authenticated = {}) {
        crypto::initialize();
        socket_.set_send_timeout(10);
        socket_.set_receive_timeout(10);
        auto deadline = cap_deadline(std::chrono::steady_clock::now() + kHandshakeDeadline);
        std::array<Byte, crypto_kx_PUBLICKEYBYTES> public_key{};
        SessionSecret secret_key;
        const auto make_hello = [&](const Key &challenge) {
            crypto_kx_keypair(public_key.data(), secret_key.bytes.data());
            const Byte our_role = client_ ? kClientRole : kServerRole;
            const Bytes unsigned_hello =
                peer_hello(network_, our_role, identity_.public_key, public_key, challenge);
            const Signature hello_signature = identity_.sign(peer_hello_digest(unsigned_hello));
            Writer hello;
            hello.raw(unsigned_hello);
            hello.fixed(hello_signature);
            return std::move(hello).take();
        };

        Bytes ours;
        Bytes theirs(kPeerHelloSize);
        std::array<Byte, crypto_kx_PUBLICKEYBYTES> peer_key{};
        if (client_) {
            Bytes prelude(kCookiePreludeSize);
            if (!socket_.receive_exact_until(prelude, deadline)) {
                throw Error("peer closed before sending a responder cookie");
            }
            const Key cookie = decode_cookie_prelude(prelude, network_);
            ours = make_hello(cookie);
            socket_.send_all_until(ours, deadline);
            if (!socket_.receive_exact_until(theirs, deadline)) {
                throw Error("peer closed during handshake");
            }
            peer_key = validate_peer_hello(theirs, std::nullopt);
        } else {
            if (!expected_cookie || prefetched_hello.size() != theirs.size()) {
                throw Error("inbound peer handshake is missing its responder cookie state");
            }
            std::copy(prefetched_hello.begin(), prefetched_hello.end(), theirs.begin());
            peer_key = validate_peer_hello(theirs, expected_cookie);
            if (!on_authenticated) {
                throw Error("inbound peer handshake has no admission callback");
            }
            on_authenticated(peer_identity_, peer_trusted_);
            if (!peer_handshake_budget_ || !global_handshake_budget_ ||
                !peer_handshake_budget_->consume_with(*global_handshake_budget_)) {
                throw Error("authenticated peer handshake budget exceeded");
            }
            // Inbound work is deliberately ordered after the allowlist and
            // peer-signature checks, so random TCP clients cannot force local
            // X25519 generation or an Ed25519 signature.
            const Key server_challenge =
                fixed_bytes<32>(crypto::random_bytes(32), "peer challenge");
            ours = make_hello(server_challenge);
            deadline = cap_deadline(std::chrono::steady_clock::now() + kHandshakeDeadline);
            socket_.send_all_until(ours, deadline);
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
        confirm_transcript(ours, theirs, deadline);
        socket_.set_receive_timeout(static_cast<int>(idle_timeout_seconds_));
    }

    void set_peer_budgets(std::shared_ptr<TrafficBudget> ingress,
                          std::shared_ptr<TrafficBudget> egress,
                          std::shared_ptr<HandshakeBudget> handshakes) {
        peer_ingress_ = std::move(ingress);
        peer_egress_ = std::move(egress);
        peer_handshake_budget_ = std::move(handshakes);
    }

    void activate() {
        if (!peer_ingress_ || !peer_egress_ || !peer_handshake_budget_) {
            throw Error("peer traffic budgets were not attached");
        }
        ready_.store(true);
    }

    const PublicKey &peer_identity() const noexcept {
        return peer_identity_;
    }

    bool peer_is_trusted() const noexcept {
        return peer_trusted_;
    }

    bool send_find_nodes(const Hash &target) {
        std::uint64_t request_id = 0;
        {
            std::lock_guard lock(discovery_requests_mutex_);
            const auto now = std::chrono::steady_clock::now();
            std::erase_if(outstanding_discovery_requests_,
                          [&](const auto &entry) { return entry.second <= now; });
            if (outstanding_discovery_requests_.size() >= kMaximumOutstandingDiscoveryRequests) {
                return false;
            }
            for (int attempt = 0; attempt < 8; ++attempt) {
                const Bytes random = crypto::random_bytes(8);
                Reader reader(random);
                request_id = reader.u64();
                if (request_id != 0 && !outstanding_discovery_requests_.contains(request_id)) {
                    break;
                }
                request_id = 0;
            }
            if (request_id == 0) {
                throw Error("could not allocate a discovery request ID");
            }
            outstanding_discovery_requests_[request_id] = now + kDiscoveryRequestDeadline;
        }
        try {
            send(FrameType::find_nodes, encode_find_nodes(request_id, target));
        } catch (...) {
            std::lock_guard lock(discovery_requests_mutex_);
            outstanding_discovery_requests_.erase(request_id);
            throw;
        }
        return true;
    }

    bool consume_discovery_response(std::uint64_t request_id) {
        std::lock_guard lock(discovery_requests_mutex_);
        const auto found = outstanding_discovery_requests_.find(request_id);
        if (found == outstanding_discovery_requests_.end() ||
            found->second <= std::chrono::steady_clock::now()) {
            if (found != outstanding_discovery_requests_.end()) {
                outstanding_discovery_requests_.erase(found);
            }
            return false;
        }
        outstanding_discovery_requests_.erase(found);
        return true;
    }

  private:
    std::array<Byte, crypto_kx_PUBLICKEYBYTES>
    validate_peer_hello(std::span<const Byte> hello, const std::optional<Key> &expected_cookie) {
        if (hello.size() != kPeerHelloSize) {
            throw Error("peer hello has an invalid length");
        }
        Reader reader(hello);
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
        const Byte peer_role = reader.u8();
        if (peer_role != (client_ ? kServerRole : kClientRole)) {
            throw Error("peer handshake role is invalid");
        }
        const PublicKey peer_identity = reader.fixed<32>("peer identity key");
        if (peer_identity == identity_.public_key) {
            throw Error("peer attempted to use the local node identity");
        }
        const bool trusted = std::find(trusted_peer_keys_.begin(), trusted_peer_keys_.end(),
                                       peer_identity) != trusted_peer_keys_.end();
        if (expected_identity_ && peer_identity != *expected_identity_) {
            throw Error("discovered endpoint returned another peer identity");
        }
        if (!allow_unknown_ && !trusted && !expected_identity_) {
            throw Error("peer identity is not in the configured allowlist");
        }
        const auto peer_key = reader.fixed<crypto_kx_PUBLICKEYBYTES>("peer session key");
        const Key peer_challenge = reader.fixed<32>("peer challenge");
        if (expected_cookie && sodium_memcmp(peer_challenge.data(), expected_cookie->data(),
                                             peer_challenge.size()) != 0) {
            throw Error("peer handshake does not bind the responder cookie");
        }
        const Signature peer_signature = reader.fixed<64>("peer hello signature");
        if (!reader.empty()) {
            throw Error("peer handshake has trailing bytes");
        }
        const auto peer_unsigned = hello.first(hello.size() - peer_signature.size());
        if (!crypto::verify(peer_identity, peer_hello_digest(peer_unsigned), peer_signature)) {
            throw Error("peer handshake signature is invalid");
        }
        peer_identity_ = peer_identity;
        peer_trusted_ = trusted;
        return peer_key;
    }

  public:
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
        if (!peer_egress_->consume_frame_with(*global_egress_, encrypted_size + 4)) {
            throw Error("outbound peer traffic budget exceeded");
        }
        const std::size_t expensive_items = cryptographic_items(type, payload);
        if (!peer_egress_->consume_events_with(*global_egress_, expensive_items)) {
            throw Error("outbound peer cryptographic-item budget exceeded");
        }
        Writer header_writer;
        header_writer.u32(static_cast<std::uint32_t>(encrypted_size));
        const Bytes header = std::move(header_writer).take();
        if (tx_counter_ == std::numeric_limits<std::uint64_t>::max()) {
            throw Error("peer frame nonce space exhausted");
        }
        const Nonce nonce = counter_nonce(tx_counter_++);
        const Bytes ciphertext = crypto::encrypt(tx_key_, nonce, plaintext, header);
        const auto deadline = cap_deadline(std::chrono::steady_clock::now() + kFrameWriteDeadline);
        socket_.send_all_until(header, deadline);
        socket_.send_all_until(ciphertext, deadline);
    }

    std::pair<FrameType, Bytes> receive() {
        std::array<Byte, 4> header{};
        const auto idle_deadline = cap_deadline(std::chrono::steady_clock::now() +
                                                std::chrono::seconds(idle_timeout_seconds_));
        if (!socket_.receive_exact_until(header, idle_deadline)) {
            throw Error("peer closed the connection");
        }
        Reader header_reader(header);
        const std::size_t size = header_reader.u32();
        if (size < crypto_aead_xchacha20poly1305_ietf_ABYTES + 1 || size > kMaximumFrame) {
            throw Error("peer frame has an invalid length");
        }
        if (!peer_ingress_->consume_frame_with(*global_ingress_, size + header.size())) {
            throw Error("inbound peer traffic budget exceeded");
        }
        Bytes ciphertext(size);
        if (!socket_.receive_exact_until(
                ciphertext, cap_deadline(std::chrono::steady_clock::now() + kFrameReadDeadline))) {
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
        const std::span<const Byte> payload(plaintext->data() + 1, plaintext->size() - 1);
        const std::size_t expensive_items = cryptographic_items(type, payload);
        if (!peer_ingress_->consume_events_with(*global_ingress_, expensive_items)) {
            throw Error("inbound peer cryptographic-item budget exceeded");
        }
        return {type, Bytes(plaintext->begin() + 1, plaintext->end())};
    }

    void close() noexcept {
        socket_.close();
    }
    bool ready() const noexcept {
        return ready_.load();
    }

  private:
    std::chrono::steady_clock::time_point
    cap_deadline(std::chrono::steady_clock::time_point candidate) const noexcept {
        return hard_deadline_ ? std::min(candidate, *hard_deadline_) : candidate;
    }

    void confirm_transcript(std::span<const Byte> ours, std::span<const Byte> theirs,
                            std::chrono::steady_clock::time_point deadline) {
        const std::span<const Byte> client_hello = client_ ? ours : theirs;
        const std::span<const Byte> server_hello = client_ ? theirs : ours;
        const Hash transcript =
            crypto::hash("kairc/peer-transcript/v2", {client_hello, server_hello});

        const Nonce nonce = counter_nonce(0);
        const std::size_t encrypted_size =
            transcript.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        Writer header_writer;
        header_writer.u32(static_cast<std::uint32_t>(encrypted_size));
        const Bytes header = std::move(header_writer).take();
        const Bytes ciphertext = crypto::encrypt(tx_key_, nonce, transcript, header);
        socket_.send_all_until(header, deadline);
        socket_.send_all_until(ciphertext, deadline);

        std::array<Byte, 4> peer_header{};
        if (!socket_.receive_exact_until(peer_header, deadline)) {
            throw Error("peer closed before transcript confirmation");
        }
        Reader peer_header_reader(peer_header);
        if (peer_header_reader.u32() != encrypted_size) {
            throw Error("peer transcript confirmation has an invalid length");
        }
        Bytes peer_ciphertext(encrypted_size);
        if (!socket_.receive_exact_until(peer_ciphertext, deadline)) {
            throw Error("peer closed during transcript confirmation");
        }
        const auto peer_transcript = crypto::decrypt(rx_key_, nonce, peer_ciphertext, peer_header);
        if (!peer_transcript || peer_transcript->size() != transcript.size() ||
            sodium_memcmp(peer_transcript->data(), transcript.data(), transcript.size()) != 0) {
            throw Error("peer transcript confirmation failed");
        }
        tx_counter_ = 1;
        rx_counter_ = 1;
    }

    Socket socket_;
    Hash network_{};
    bool client_ = false;
    std::uint64_t idle_timeout_seconds_ = 0;
    std::shared_ptr<TrafficBudget> peer_ingress_;
    std::shared_ptr<TrafficBudget> peer_egress_;
    std::shared_ptr<HandshakeBudget> peer_handshake_budget_;
    std::shared_ptr<TrafficBudget> global_ingress_;
    std::shared_ptr<TrafficBudget> global_egress_;
    std::shared_ptr<HandshakeBudget> global_handshake_budget_;
    const crypto::Identity &identity_;
    const std::vector<PublicKey> &trusted_peer_keys_;
    bool allow_unknown_ = false;
    std::optional<PublicKey> expected_identity_;
    std::optional<std::chrono::steady_clock::time_point> hard_deadline_;
    PublicKey peer_identity_{};
    bool peer_trusted_ = false;
    Key rx_key_{};
    Key tx_key_{};
    std::uint64_t rx_counter_ = 0;
    std::uint64_t tx_counter_ = 0;
    std::atomic<bool> ready_{false};
    std::mutex write_mutex_;
    std::mutex discovery_requests_mutex_;
    std::unordered_map<std::uint64_t, std::chrono::steady_clock::time_point>
        outstanding_discovery_requests_;
};

} // namespace

class PeerNetwork::Impl {
  public:
    Impl(Node &node, std::optional<HostPort> listen, std::vector<PeerEndpoint> peers,
         PeerLimits limits, const std::optional<Key> &identity_seed,
         std::vector<PublicKey> trusted_peer_keys, bool allow_unknown_inbound,
         bool allow_unknown_outbound, PeerDiscoveryOptions discovery,
         std::optional<HostPort> tor_proxy)
        : node_(node), listen_address_(std::move(listen)), peers_(std::move(peers)),
          limits_(limits), identity_(identity_seed ? crypto::Identity::from_seed(*identity_seed)
                                                   : crypto::Identity::generate()),
          trusted_peer_keys_(std::move(trusted_peer_keys)),
          allow_unknown_inbound_(allow_unknown_inbound),
          allow_unknown_outbound_(allow_unknown_outbound), discovery_(std::move(discovery)),
          tor_proxy_(std::move(tor_proxy)), directory_(node_.network(), identity_.public_key),
          global_ingress_(std::make_shared<TrafficBudget>(limits.global_bytes_per_minute,
                                                          limits.global_frames_per_minute,
                                                          limits.global_events_per_minute)),
          global_egress_(std::make_shared<TrafficBudget>(limits.global_bytes_per_minute,
                                                         limits.global_frames_per_minute,
                                                         limits.global_events_per_minute)),
          global_handshake_budget_(std::make_shared<HandshakeBudget>(
              limits.global_authenticated_handshakes_per_minute)) {
        const auto now = std::chrono::steady_clock::now();
        for (const PublicKey &peer : trusted_peer_keys_) {
            peer_budgets_.emplace(peer, PeerBudgetEntry{
                                            .ingress = std::make_shared<TrafficBudget>(
                                                limits_.bytes_per_minute, limits_.frames_per_minute,
                                                limits_.events_per_minute),
                                            .egress = std::make_shared<TrafficBudget>(
                                                limits_.bytes_per_minute, limits_.frames_per_minute,
                                                limits_.events_per_minute),
                                            .handshakes = std::make_shared<HandshakeBudget>(
                                                limits_.authenticated_handshakes_per_minute),
                                            .sessions = 0,
                                            .trusted = true,
                                            .inactive_since = now,
                                        });
        }
        initialize_discovery();
    }

    ~Impl() {
        stop();
    }

    void start() {
        if (running_.exchange(true)) {
            return;
        }
        try {
            if (listen_address_) {
                listener_ =
                    Socket::listen_tcp(*listen_address_, static_cast<int>(kMaximumPendingHellos));
                accept_thread_ = std::thread([this] { accept_loop(); });
            }
            for (const PeerEndpoint &endpoint : peers_) {
                connector_threads_.emplace_back([this, endpoint] { connector_loop(endpoint); });
            }
            if (discovery_.mode != DiscoveryMode::off) {
                for (std::size_t index = 0; index < kDiscoveryWorkerCount; ++index) {
                    const bool trusted_only = index == 0;
                    discovery_workers_.emplace_back(
                        [this, trusted_only] { discovery_connector_loop(trusted_only); });
                }
                discovery_maintenance_thread_ =
                    std::thread([this] { discovery_maintenance_loop(); });
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
        discovery_changed_.notify_all();
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
        for (std::thread &worker : discovery_workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        discovery_workers_.clear();
        if (discovery_maintenance_thread_.joinable()) {
            discovery_maintenance_thread_.join();
        }

        {
            std::unique_lock lock(sessions_mutex_);
            sessions_changed_.wait(
                lock, [this] { return active_sessions_ == 0 && inbound_handshakes_ == 0; });
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
    struct InboundAdmission {
        Bytes hello;
        Key cookie{};
        PublicKey claimed_identity{};
        std::optional<std::string> source_key;
    };

    struct DiscoveryBackoff {
        std::size_t failures = 0;
        std::chrono::steady_clock::time_point next_attempt{};
        std::chrono::steady_clock::time_point retain_until{};
    };

    struct DiscoveryDial {
        PeerRecord record;
        SessionReservation reservation = SessionReservation::trusted_discovery_session;
    };

    bool discovery_accepts(const PublicKey &identity) const {
        if (discovery_.mode == DiscoveryMode::open) {
            return true;
        }
        if (discovery_.mode != DiscoveryMode::trusted) {
            return false;
        }
        return std::find(trusted_peer_keys_.begin(), trusted_peer_keys_.end(), identity) !=
               trusted_peer_keys_.end();
    }

    bool discovery_identity_is_trusted(const PublicKey &identity) const {
        return std::find(trusted_peer_keys_.begin(), trusted_peer_keys_.end(), identity) !=
               trusted_peer_keys_.end();
    }

    bool link_can_use_discovery(const std::shared_ptr<Link> &link) const noexcept {
        return discovery_.mode == DiscoveryMode::open ||
               (discovery_.mode == DiscoveryMode::trusted && link->peer_is_trusted());
    }

    PeerRecordStoreStatus store_remote_peer_record(const PeerRecord &record,
                                                   std::uint64_t observed_at_seconds,
                                                   bool trusted_priority) {
        // A valid remote record can be unusable solely because of local durable
        // state (stale watermark, protected retirement, or quota).  Return that
        // semantic result to admission; it is not evidence against a NODES
        // relay.  Actual SQLite/serialization failures still throw.
        return node_.store_peer_record(record, observed_at_seconds, trusted_priority);
    }

    void store_local_peer_record_or_throw(const PeerRecord &record,
                                          std::uint64_t observed_at_seconds) {
        const PeerRecordStoreStatus status =
            node_.store_peer_record(record, observed_at_seconds, true);
        if (status == PeerRecordStoreStatus::stored || status == PeerRecordStoreStatus::duplicate) {
            return;
        }
        if (status == PeerRecordStoreStatus::quota_exceeded) {
            throw Error("persistent peer record quota reached");
        }
        if (status == PeerRecordStoreStatus::equivocation) {
            throw Error("local peer record conflicts with a persisted sequence");
        }
        if (status == PeerRecordStoreStatus::protected_downgrade) {
            throw Error("local peer record lost its protected storage class");
        }
        throw Error("local peer record sequence is older than persistent state");
    }

    void initialize_discovery() {
        if (discovery_.mode == DiscoveryMode::off) {
            return;
        }
        const std::uint64_t now = unix_time_seconds();
        std::optional<PeerRecord> previous_self;
        for (const Bytes &wire : node_.load_peer_records(now)) {
            PeerRecord record = PeerRecord::deserialize(wire);
            if (record.identity == identity_.public_key) {
                record.validate(node_.network(), now);
                previous_self = std::move(record);
                continue;
            }
            if (!discovery_accepts(record.identity)) {
                continue;
            }
            const bool identity_anchored = node_.peer_record_has_verified_history(record.identity);
            const PeerRecordInsertStatus status =
                directory_.insert(record, now,
                                  PeerRecordAdmission{
                                      .identity_anchored = identity_anchored,
                                      .priority = discovery_identity_is_trusted(record.identity)
                                                      ? PeerRecordPriority::trusted
                                                  : (record.tombstone() && identity_anchored)
                                                      ? PeerRecordPriority::anchored_withdrawal
                                                      : PeerRecordPriority::ordinary,
                                  });
            if (status == PeerRecordInsertStatus::equivocation ||
                status == PeerRecordInsertStatus::stale) {
                throw Error("persistent peer record state is inconsistent");
            }
        }
        node_.prune_peer_records(now);

        if (!discovery_.advertised_endpoints.empty()) {
            const std::uint64_t sequence =
                node_.next_peer_record_sequence(identity_.public_key, unix_time_ms());
            self_record_ = PeerRecord::create(
                node_.network(), identity_, sequence, now, now + kPeerRecordLifetimeSeconds,
                kPeerCapabilityEventGossip, discovery_.advertised_endpoints);
            store_local_peer_record_or_throw(*self_record_, now);
        } else if (previous_self && !previous_self->tombstone()) {
            const std::uint64_t sequence =
                node_.next_peer_record_sequence(identity_.public_key, unix_time_ms());
            self_record_ = PeerRecord::create(node_.network(), identity_, sequence, now,
                                              now + kPeerRecordMaximumLifetimeSeconds, 0, {});
            store_local_peer_record_or_throw(*self_record_, now);
        } else if (previous_self) {
            self_record_ = std::move(previous_self);
        }
    }

    void accept_loop() {
        struct PendingHello {
            Socket socket;
            Key cookie{};
            Bytes prelude;
            std::size_t sent = 0;
            Bytes hello = Bytes(kPeerHelloSize);
            std::size_t received = 0;
            std::chrono::steady_clock::time_point deadline;
            std::optional<std::string> source_key;
        };
        std::vector<PendingHello> pending;
        const auto erase_pending = [&](std::size_t index, bool release_source) {
            if (release_source) {
                release_preauth_source(pending[index].source_key);
            }
            pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(index));
        };

        const auto accept_batch = [&] {
            // Drain a bounded batch from the kernel backlog. Accepting only one
            // socket per poll interval lets a short burst fill the listen queue,
            // while an unlimited drain could starve pending hello I/O.
            for (std::size_t accepted_count = 0;
                 accepted_count < kMaximumAcceptBatch && running_.load(); ++accepted_count) {
                try {
                    const auto wait = accepted_count == 0 ? std::chrono::milliseconds(20)
                                                          : std::chrono::milliseconds(1);
                    auto accepted = listener_.accept_until(std::chrono::steady_clock::now() + wait);
                    if (!accepted) {
                        break;
                    }
                    if (!running_.load()) {
                        accepted->close();
                        break;
                    }
                    std::optional<std::string> source_key = accepted->peer_rate_key();
                    if (!reserve_preauth_source(source_key)) {
                        accepted->close();
                        continue;
                    }
                    // A full Tor-facing queue must not become a fixed wall of
                    // silent loopback connections. Give each newcomer a chance
                    // to answer its fresh cookie by evicting the oldest
                    // unfinished admission while keeping the queue bounded.
                    if (pending.size() >= kMaximumPendingHellos) {
                        erase_pending(0, true);
                    }
                    try {
                        const Key cookie =
                            fixed_bytes<32>(crypto::random_bytes(32), "peer responder cookie");
                        pending.push_back(PendingHello{
                            .socket = std::move(*accepted),
                            .cookie = cookie,
                            .prelude = cookie_prelude(node_.network(), cookie),
                            .deadline = std::chrono::steady_clock::now() + kInboundHelloDeadline,
                            .source_key = source_key,
                        });
                    } catch (...) {
                        release_preauth_source(source_key);
                        throw;
                    }
                } catch (const std::exception &) {
                    if (running_.load()) {
                        std::cerr << "kaircd: inbound P2P accept failed\n";
                    }
                    break;
                }
            }
        };

        const auto advance_pending = [&] {
            for (std::size_t index = 0; index < pending.size();) {
                PendingHello &entry = pending[index];
                if (std::chrono::steady_clock::now() >= entry.deadline) {
                    erase_pending(index, true);
                    continue;
                }
                if (entry.sent != entry.prelude.size()) {
                    std::optional<std::size_t> sent;
                    try {
                        sent = entry.socket.send_some(
                            std::span<const Byte>(entry.prelude).subspan(entry.sent));
                    } catch (const Error &) {
                        erase_pending(index, true);
                        continue;
                    }
                    if (!sent) {
                        ++index;
                        continue;
                    }
                    if (*sent == 0) {
                        erase_pending(index, true);
                        continue;
                    }
                    entry.sent += *sent;
                    if (entry.sent != entry.prelude.size()) {
                        ++index;
                        continue;
                    }
                }

                std::optional<std::size_t> received;
                try {
                    received = entry.socket.receive_some(
                        std::span<Byte>(entry.hello).subspan(entry.received));
                } catch (const Error &) {
                    erase_pending(index, true);
                    continue;
                }
                if (!received) {
                    ++index;
                    continue;
                }
                if (*received == 0) {
                    erase_pending(index, true);
                    continue;
                }
                entry.received += *received;
                if (entry.received != entry.hello.size()) {
                    ++index;
                    continue;
                }

                std::optional<PublicKey> claimed_identity;
                try {
                    claimed_identity = precheck_client_hello(
                        entry.hello, entry.cookie, node_.network(), identity_.public_key,
                        trusted_peer_keys_, allow_unknown_inbound_);
                } catch (const Error &) {
                    erase_pending(index, true);
                    continue;
                }
                Socket socket = std::move(entry.socket);
                InboundAdmission admission{
                    .hello = std::move(entry.hello),
                    .cookie = entry.cookie,
                    .claimed_identity = *claimed_identity,
                    .source_key = std::move(entry.source_key),
                };
                erase_pending(index, false);
                if (!reserve_inbound_handshake(admission.claimed_identity)) {
                    release_preauth_source(admission.source_key);
                    socket.close();
                    continue;
                }
                const PublicKey reserved_identity = admission.claimed_identity;
                const std::optional<std::string> reserved_source = admission.source_key;
                try {
                    std::thread([this, socket = std::move(socket),
                                 admission = std::move(admission)]() mutable {
                        run_reserved_link(std::move(socket), false,
                                          SessionReservation::inbound_handshake,
                                          std::move(admission));
                    }).detach();
                } catch (...) {
                    release_reservation(SessionReservation::inbound_handshake, reserved_identity);
                    release_preauth_source(reserved_source);
                }
            }
        };

        while (running_.load()) {
            // Service cookie replies before admitting another batch so a full
            // queue cannot evict a complete, authenticated hello that is already
            // readable on an older socket.
            advance_pending();
            accept_batch();
        }
        for (const PendingHello &entry : pending) {
            release_preauth_source(entry.source_key);
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
                if (reserve_outbound_session()) {
                    run_reserved_link(std::move(socket), true, SessionReservation::outbound_session,
                                      {}, endpoint.expected_identity);
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

    void prune_discovery_backoff_locked(std::uint64_t now_seconds) {
        directory_.prune(now_seconds);
        const auto now = std::chrono::steady_clock::now();
        std::erase_if(discovery_backoff_, [&](const auto &item) {
            if (active_discovery_dials_.contains(item.first)) {
                return false;
            }
            // Keep a failed identity's state after a short-lived route expires.
            // Otherwise it can publish a higher-sequence short-TTL record and
            // reset the retry window without changing identity or destination.
            return item.second.retain_until <= now &&
                   !directory_.find(item.first, now_seconds).has_value();
        });
    }

    std::optional<DiscoveryDial> next_discovery_target(bool trusted_only) {
        std::unique_lock lock(discovery_mutex_);
        while (running_.load()) {
            const auto now = std::chrono::steady_clock::now();
            const std::uint64_t wall_now = unix_time_seconds();
            prune_discovery_backoff_locked(wall_now);
            if (discovery_overflow_backoff_.next_attempt > now) {
                discovery_changed_.wait_until(lock,
                                              std::min(discovery_overflow_backoff_.next_attempt,
                                                       now + std::chrono::seconds(1)),
                                              [this] { return !running_.load(); });
                continue;
            }
            const std::vector<PeerRecord> candidates =
                directory_.dial_candidates(directory_.local_node_id(), directory_.size(), wall_now);
            const auto select = [&](bool select_trusted) -> std::optional<DiscoveryDial> {
                for (const PeerRecord &record : candidates) {
                    const bool trusted = discovery_identity_is_trusted(record.identity);
                    if (trusted != select_trusted ||
                        active_discovery_dials_.contains(record.identity)) {
                        continue;
                    }
                    const auto retry = discovery_backoff_.find(record.identity);
                    if (retry != discovery_backoff_.end() && retry->second.next_attempt > now) {
                        continue;
                    }
                    const std::optional<SessionReservation> reservation =
                        reserve_discovery_session(trusted);
                    if (!reservation) {
                        continue;
                    }
                    active_discovery_dials_.insert(record.identity);
                    return DiscoveryDial{record, *reservation};
                }
                return std::nullopt;
            };
            if (const auto trusted = select(true)) {
                return trusted;
            }
            if (!trusted_only) {
                if (const auto untrusted = select(false)) {
                    return untrusted;
                }
            }
            discovery_changed_.wait_for(lock, std::chrono::seconds(1),
                                        [this] { return !running_.load(); });
        }
        return std::nullopt;
    }

    void finish_discovery_attempt(const PublicKey &identity, bool established) {
        std::lock_guard lock(discovery_mutex_);
        active_discovery_dials_.erase(identity);
        const std::uint64_t now_seconds = unix_time_seconds();
        prune_discovery_backoff_locked(now_seconds);
        const auto now = std::chrono::steady_clock::now();
        const auto update_backoff = [&](DiscoveryBackoff &backoff) {
            if (backoff.retain_until <= now) {
                backoff = DiscoveryBackoff{};
            }
            if (established) {
                backoff.failures = 0;
            } else {
                backoff.failures = std::min<std::size_t>(backoff.failures + 1, 5);
            }
            const auto multiplier = std::uint64_t{1} << backoff.failures;
            auto delay = established ? kDiscoverySuccessfulRetryDelay : kDiscoveryRetryDelay;
            if (!established) {
                delay *= static_cast<std::chrono::seconds::rep>(multiplier);
            }
            backoff.next_attempt = now + delay;
            // Preserve the failure ladder across attacker-controlled TTL expiry
            // or tombstone/live churn.  This horizon matches the durable
            // sequence watermark and remains bounded in time.
            backoff.retain_until = now + kDiscoveryBackoffRetention;
        };
        auto existing = discovery_backoff_.find(identity);
        if (existing == discovery_backoff_.end()) {
            if (discovery_backoff_.size() >= kMaximumDiscoveryBackoffEntries) {
                // Retaining recently expired routes can temporarily fill this
                // bounded map.  Escalate one shared fail-closed backoff instead
                // of silently allowing untracked identities to stay at the
                // first retry tier.  Successful sessions also retain the
                // normal ten-minute rotation delay here.
                update_backoff(discovery_overflow_backoff_);
                discovery_changed_.notify_all();
                return;
            }
            existing = discovery_backoff_.emplace(identity, DiscoveryBackoff{}).first;
        }
        update_backoff(existing->second);
        discovery_changed_.notify_all();
    }

    void discovery_connector_loop(bool trusted_only) {
        while (running_.load()) {
            std::optional<DiscoveryDial> dial = next_discovery_target(trusted_only);
            if (!dial) {
                break;
            }
            bool handed_off = false;
            for (const OnionEndpoint &address : dial->record.endpoints) {
                if (!running_.load()) {
                    break;
                }
                try {
                    if (!tor_proxy_) {
                        throw Error("discovery has no Tor proxy");
                    }
                    PeerEndpoint endpoint{
                        .transport = PeerTransport::socks5,
                        .target = HostPort{address.host, address.port},
                        .proxy = tor_proxy_,
                        .expected_identity = dial->record.identity,
                    };
                    Socket socket = Socket::connect_peer(endpoint);
                    if (!running_.load()) {
                        socket.close();
                        break;
                    }
                    const PublicKey identity = dial->record.identity;
                    std::thread([this, socket = std::move(socket), reservation = dial->reservation,
                                 discovered = dial->record, identity]() mutable {
                        run_reserved_link(
                            std::move(socket), true, reservation, {}, identity, discovered,
                            std::chrono::steady_clock::now() + kDiscoverySessionLifetime,
                            [this, identity](bool established) {
                                finish_discovery_attempt(identity, established);
                            });
                    }).detach();
                    handed_off = true;
                    break;
                } catch (const std::exception &) {
                    // Discovery endpoints are untrusted and are deliberately not logged.
                }
            }
            if (!handed_off) {
                release_reservation(dial->reservation);
                finish_discovery_attempt(dial->record.identity, false);
            }
        }
    }

    void discovery_maintenance_loop() {
        while (running_.load()) {
            {
                std::unique_lock lock(discovery_mutex_);
                discovery_changed_.wait_for(lock, std::chrono::seconds(60),
                                            [this] { return !running_.load(); });
            }
            if (!running_.load()) {
                break;
            }

            try {
                const std::uint64_t now = unix_time_seconds();
                std::optional<PeerRecord> self;
                {
                    std::lock_guard lock(discovery_mutex_);
                    directory_.prune(now);
                    prune_discovery_backoff_locked(now);
                    if (self_record_ && !self_record_->tombstone() &&
                        (self_record_->expires_at <= now ||
                         self_record_->expires_at - now <= kPeerRecordLifetimeSeconds / 2)) {
                        const std::uint64_t sequence =
                            node_.next_peer_record_sequence(identity_.public_key, unix_time_ms());
                        self_record_ = PeerRecord::create(node_.network(), identity_, sequence, now,
                                                          now + kPeerRecordLifetimeSeconds,
                                                          kPeerCapabilityEventGossip,
                                                          discovery_.advertised_endpoints);
                        store_local_peer_record_or_throw(*self_record_, now);
                    }
                    self = self_record_;
                }
                node_.prune_peer_records(now);

                std::vector<std::shared_ptr<Link>> links;
                {
                    std::lock_guard lock(links_mutex_);
                    links = links_;
                }
                Hash random_target =
                    fixed_bytes<32>(crypto::random_bytes(32), "discovery refresh target");
                for (const auto &link : links) {
                    if (!link->ready() || !link_can_use_discovery(link)) {
                        continue;
                    }
                    try {
                        if (self && self->expires_at > now) {
                            link->send(FrameType::peer_record, self->serialize());
                        }
                        static_cast<void>(link->send_find_nodes(random_target));
                    } catch (const Error &) {
                        link->close();
                    }
                }
            } catch (const std::exception &) {
                if (running_.load()) {
                    std::cerr << "kaircd: peer discovery maintenance failed\n";
                }
            }
        }
    }

    bool reserve_preauth_source(const std::optional<std::string> &source_key) {
        if (!source_key) {
            return true;
        }
        std::lock_guard lock(sessions_mutex_);
        const auto source = preauth_by_source_.find(*source_key);
        if (source != preauth_by_source_.end() &&
            source->second >= kMaximumPendingHellosPerSource) {
            return false;
        }
        ++preauth_by_source_[*source_key];
        return true;
    }

    void release_preauth_source(const std::optional<std::string> &source_key) {
        if (!source_key) {
            return;
        }
        std::lock_guard lock(sessions_mutex_);
        const auto source = preauth_by_source_.find(*source_key);
        if (source != preauth_by_source_.end() && --source->second == 0) {
            preauth_by_source_.erase(source);
        }
    }

    bool reserve_inbound_handshake(const PublicKey &claimed_identity) {
        std::lock_guard lock(sessions_mutex_);
        const auto identity = inbound_handshakes_by_identity_.find(claimed_identity);
        if (inbound_handshakes_ >= kMaximumInboundHandshakes ||
            active_sessions_ + inbound_handshakes_ >= kMaximumPeerSessions ||
            inbound_sessions_ + inbound_handshakes_ >= kMaximumInboundSessions ||
            (identity != inbound_handshakes_by_identity_.end() &&
             identity->second >= kMaximumInboundHandshakesPerIdentity)) {
            return false;
        }
        ++inbound_handshakes_;
        ++inbound_handshakes_by_identity_[claimed_identity];
        return true;
    }

    bool reserve_outbound_session() {
        std::lock_guard lock(sessions_mutex_);
        if (active_sessions_ + inbound_handshakes_ >= kMaximumPeerSessions) {
            return false;
        }
        ++active_sessions_;
        return true;
    }

    std::optional<SessionReservation> reserve_discovery_session(bool trusted) {
        std::lock_guard lock(sessions_mutex_);
        if (active_sessions_ + inbound_handshakes_ >= kMaximumPeerSessions ||
            discovery_sessions_ >= kMaximumDiscoverySessions ||
            (!trusted && untrusted_discovery_sessions_ >= kMaximumUntrustedDiscoverySessions)) {
            return std::nullopt;
        }
        ++active_sessions_;
        ++discovery_sessions_;
        if (!trusted) {
            ++untrusted_discovery_sessions_;
        }
        return trusted ? SessionReservation::trusted_discovery_session
                       : SessionReservation::untrusted_discovery_session;
    }

    bool promote_inbound_handshake(const PublicKey &claimed_identity) {
        std::lock_guard lock(sessions_mutex_);
        const auto identity = inbound_handshakes_by_identity_.find(claimed_identity);
        if (inbound_handshakes_ == 0 || identity == inbound_handshakes_by_identity_.end() ||
            identity->second == 0) {
            return false;
        }
        if (active_sessions_ >= kMaximumPeerSessions ||
            inbound_sessions_ >= kMaximumInboundSessions) {
            return false;
        }
        --inbound_handshakes_;
        if (--identity->second == 0) {
            inbound_handshakes_by_identity_.erase(identity);
        }
        ++active_sessions_;
        ++inbound_sessions_;
        sessions_changed_.notify_all();
        return true;
    }

    void release_reservation(SessionReservation reservation,
                             const std::optional<PublicKey> &claimed_identity = std::nullopt) {
        std::lock_guard lock(sessions_mutex_);
        if (reservation == SessionReservation::inbound_handshake) {
            if (inbound_handshakes_ > 0) {
                --inbound_handshakes_;
            }
            if (claimed_identity) {
                const auto identity = inbound_handshakes_by_identity_.find(*claimed_identity);
                if (identity != inbound_handshakes_by_identity_.end() && --identity->second == 0) {
                    inbound_handshakes_by_identity_.erase(identity);
                }
            }
        } else if (reservation == SessionReservation::inbound_session) {
            if (active_sessions_ > 0) {
                --active_sessions_;
            }
            if (inbound_sessions_ > 0) {
                --inbound_sessions_;
            }
        } else if (reservation == SessionReservation::outbound_session) {
            if (active_sessions_ > 0) {
                --active_sessions_;
            }
        } else {
            if (active_sessions_ > 0) {
                --active_sessions_;
            }
            if (discovery_sessions_ > 0) {
                --discovery_sessions_;
            }
            if (reservation == SessionReservation::untrusted_discovery_session &&
                untrusted_discovery_sessions_ > 0) {
                --untrusted_discovery_sessions_;
            }
        }
        sessions_changed_.notify_all();
    }

    struct PeerBudgetEntry {
        std::shared_ptr<TrafficBudget> ingress;
        std::shared_ptr<TrafficBudget> egress;
        std::shared_ptr<HandshakeBudget> handshakes;
        std::size_t sessions = 0;
        bool trusted = false;
        std::chrono::steady_clock::time_point inactive_since{};
    };

    bool attach_peer_budget(const std::shared_ptr<Link> &link, const PublicKey &identity,
                            bool trusted) {
        const auto now = std::chrono::steady_clock::now();
        std::shared_ptr<TrafficBudget> ingress;
        std::shared_ptr<TrafficBudget> egress;
        std::shared_ptr<HandshakeBudget> peer_handshakes;
        {
            std::lock_guard lock(peer_budgets_mutex_);
            std::erase_if(peer_budgets_, [&](const auto &item) {
                const PeerBudgetEntry &entry = item.second;
                return entry.sessions == 0 && !entry.trusted &&
                       now - entry.inactive_since >= kBudgetWindow;
            });

            auto entry = peer_budgets_.find(identity);
            if (entry == peer_budgets_.end()) {
                const std::size_t maximum_entries =
                    trusted_peer_keys_.size() + kMaximumUnknownIdentityBudgets;
                if (peer_budgets_.size() >= maximum_entries) {
                    return false;
                }
                PeerBudgetEntry fresh{
                    .ingress = std::make_shared<TrafficBudget>(limits_.bytes_per_minute,
                                                               limits_.frames_per_minute,
                                                               limits_.events_per_minute),
                    .egress = std::make_shared<TrafficBudget>(limits_.bytes_per_minute,
                                                              limits_.frames_per_minute,
                                                              limits_.events_per_minute),
                    .handshakes = std::make_shared<HandshakeBudget>(
                        limits_.authenticated_handshakes_per_minute),
                    .sessions = 0,
                    .trusted = trusted,
                    .inactive_since = now,
                };
                entry = peer_budgets_.emplace(identity, std::move(fresh)).first;
            }
            if (entry->second.sessions >= kMaximumSessionsPerIdentity) {
                return false;
            }
            ++entry->second.sessions;
            entry->second.trusted = entry->second.trusted || trusted;
            ingress = entry->second.ingress;
            egress = entry->second.egress;
            peer_handshakes = entry->second.handshakes;
        }
        link->set_peer_budgets(std::move(ingress), std::move(egress), std::move(peer_handshakes));
        return true;
    }

    void detach_peer_budget(const PublicKey &identity) {
        std::lock_guard lock(peer_budgets_mutex_);
        const auto entry = peer_budgets_.find(identity);
        if (entry == peer_budgets_.end() || entry->second.sessions == 0) {
            return;
        }
        --entry->second.sessions;
        if (entry->second.sessions == 0) {
            entry->second.inactive_since = std::chrono::steady_clock::now();
        }
    }

    bool run_reserved_link(
        Socket socket, bool client, SessionReservation initial_reservation,
        std::optional<InboundAdmission> admission,
        std::optional<PublicKey> expected_identity = std::nullopt,
        std::optional<PeerRecord> discovered_record = std::nullopt,
        std::optional<std::chrono::steady_clock::time_point> session_deadline = std::nullopt,
        std::function<void(bool)> completion = {}) {
        struct SessionGuard {
            Impl *owner;
            SessionReservation reservation;
            std::optional<PublicKey> claimed_identity;
            ~SessionGuard() {
                owner->release_reservation(reservation, claimed_identity);
            }
        } guard{this, initial_reservation,
                admission ? std::optional(admission->claimed_identity) : std::nullopt};
        struct SourceGuard {
            Impl *owner;
            std::optional<std::string> source_key;
            bool active = true;
            void release() {
                if (active) {
                    owner->release_preauth_source(source_key);
                    active = false;
                }
            }
            ~SourceGuard() {
                release();
            }
        } source_guard{this, admission ? admission->source_key : std::nullopt};
        std::shared_ptr<Link> link;
        std::optional<PublicKey> attached_identity;
        bool established = false;
        struct CompletionGuard {
            std::function<void(bool)> callback;
            bool &established;
            ~CompletionGuard() {
                if (callback) {
                    try {
                        callback(established);
                    } catch (...) {
                        // Completion bookkeeping must never unwind from a guard.
                    }
                }
            }
        } completion_guard{std::move(completion), established};
        try {
            if (!running_.load()) {
                return false;
            }
            link = std::make_shared<Link>(
                std::move(socket), node_.network(), client, limits_, global_ingress_,
                global_egress_, client ? nullptr : global_handshake_budget_, identity_,
                trusted_peer_keys_, client ? allow_unknown_outbound_ : allow_unknown_inbound_,
                expected_identity, session_deadline);
            {
                std::lock_guard lock(links_mutex_);
                if (!running_.load()) {
                    link->close();
                    return false;
                }
                links_.push_back(link);
            }
            if (admission) {
                link->establish(
                    admission->hello, admission->cookie,
                    [&](const PublicKey &authenticated_identity, bool trusted) {
                        if (authenticated_identity != admission->claimed_identity) {
                            throw Error("peer identity changed after admission precheck");
                        }
                        if (!attach_peer_budget(link, authenticated_identity, trusted)) {
                            throw Error("peer identity session or budget capacity reached");
                        }
                        attached_identity = authenticated_identity;
                    });
            } else {
                link->establish();
                if (!attach_peer_budget(link, link->peer_identity(), link->peer_is_trusted())) {
                    throw Error("peer identity session or budget capacity reached");
                }
                attached_identity = link->peer_identity();
            }
            source_guard.release();
            if (!client) {
                if (!admission || !promote_inbound_handshake(admission->claimed_identity)) {
                    throw Error("inbound peer session capacity reached");
                }
                guard.reservation = SessionReservation::inbound_session;
            }
            link->activate();
            established = true;
            if (discovered_record) {
                std::lock_guard discovery_lock(discovery_mutex_);
                const std::uint64_t now = unix_time_seconds();
                if (node_.mark_peer_record_verified(discovered_record->identity,
                                                    discovered_record->sequence, now)) {
                    directory_.mark_verified(discovered_record->identity,
                                             discovered_record->sequence, now);
                }
            }
            const std::vector<Hash> inventory = node_.recent_ids(kInventoryLimit);
            link->send(FrameType::inventory, encode_ids(inventory));
            send_discovery_intro(link);
            while (running_.load() &&
                   (!session_deadline || std::chrono::steady_clock::now() < *session_deadline)) {
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
        if (attached_identity) {
            detach_peer_budget(*attached_identity);
        }
        return established;
    }

    std::vector<PeerRecord> closest_discovery_records(const Hash &target) {
        const std::uint64_t now = unix_time_seconds();
        std::lock_guard lock(discovery_mutex_);
        std::vector<PeerRecord> records = directory_.closest(target, kDiscoveryResponseLimit, now);
        if (self_record_ && self_record_->expires_at > now) {
            records.push_back(*self_record_);
            std::sort(records.begin(), records.end(),
                      [&](const PeerRecord &left, const PeerRecord &right) {
                          return peer_record_distance_less(left, right, target);
                      });
            if (records.size() > kDiscoveryResponseLimit) {
                records.resize(kDiscoveryResponseLimit);
            }
        }
        return records;
    }

    void verify_discovery_record_or_throw(const PeerRecord &record) {
        if (!discovery_verification_slots_.try_acquire()) {
            throw Error("peer record verification capacity is saturated");
        }
        struct VerificationGuard {
            std::counting_semaphore<256> &slots;
            ~VerificationGuard() {
                slots.release();
            }
        } verification_guard{discovery_verification_slots_};
        record.verify_signature();
    }

    PeerRecordInsertStatus admit_peer_record(const PeerRecord &record,
                                             bool tolerate_relay_time_skew = false) {
        const std::uint64_t now = unix_time_seconds();
        // A third-party NODES record can expire in transit, or cross the clock
        // skew boundary between two honest nodes.  That is not attributable to
        // the relay.  Cross-network and structural failures still reach the
        // normal hard precheck below.
        if (tolerate_relay_time_skew && record.network == node_.network() &&
            !record.time_window_is_valid(now)) {
            // Authenticate the subject before treating the temporal failure as
            // benign; a relay still owns malformed or forged response data.
            verify_discovery_record_or_throw(record);
            return PeerRecordInsertStatus::stale;
        }
        record.precheck(node_.network(), now);
        if (!discovery_accepts(record.identity)) {
            return PeerRecordInsertStatus::stale;
        }
        const bool priority = discovery_identity_is_trusted(record.identity);
        {
            std::lock_guard lock(discovery_mutex_);
            const PeerRecordInsertStatus preview =
                directory_.preview_insert(record, now,
                                          PeerRecordAdmission{
                                              .priority = priority ? PeerRecordPriority::trusted
                                                                   : PeerRecordPriority::ordinary,
                                          });
            if (preview != PeerRecordInsertStatus::inserted &&
                preview != PeerRecordInsertStatus::updated) {
                // A same-sequence conflict is only attributable after its
                // subject signature verifies.  In particular, a NODES relay
                // must not be disconnected for unverified third-party bytes.
                if (preview != PeerRecordInsertStatus::equivocation &&
                    preview != PeerRecordInsertStatus::unanchored_tombstone &&
                    preview != PeerRecordInsertStatus::bucket_full) {
                    return preview;
                }
            }
        }
        verify_discovery_record_or_throw(record);

        std::lock_guard lock(discovery_mutex_);
        const bool identity_anchored =
            record.tombstone() && node_.peer_record_has_verified_history(record.identity);
        const PeerRecordPriority routing_priority = priority ? PeerRecordPriority::trusted
                                                    : (record.tombstone() && identity_anchored)
                                                        ? PeerRecordPriority::anchored_withdrawal
                                                        : PeerRecordPriority::ordinary;
        const PeerRecordAdmission admission{
            .identity_anchored = identity_anchored,
            .priority = routing_priority,
        };
        const PeerRecordInsertStatus preview = directory_.preview_insert(record, now, admission);
        if (preview != PeerRecordInsertStatus::inserted &&
            preview != PeerRecordInsertStatus::updated) {
            if (preview == PeerRecordInsertStatus::equivocation) {
                return preview;
            }
            if ((preview == PeerRecordInsertStatus::bucket_full ||
                 preview == PeerRecordInsertStatus::unanchored_tombstone) &&
                (priority || node_.peer_record_is_known(record.identity))) {
                // Directory capacity governs routing only.  A known identity's
                // durable sequence watermark must still advance so restart or
                // eviction cannot revive an older record.
                if (store_remote_peer_record(record, now, priority) ==
                    PeerRecordStoreStatus::equivocation) {
                    return PeerRecordInsertStatus::equivocation;
                }
            }
            return preview;
        }
        // Persist the sequence high-water before making the route visible.  If
        // durable state rejects rollback/equivocation, no stale in-memory route
        // can leak into dialing or gossip.
        const PeerRecordStoreStatus stored = store_remote_peer_record(record, now, priority);
        if (stored == PeerRecordStoreStatus::equivocation) {
            return PeerRecordInsertStatus::equivocation;
        }
        if (stored == PeerRecordStoreStatus::stale ||
            stored == PeerRecordStoreStatus::protected_downgrade) {
            // The durable watermark is newer, or the subject was protected by
            // a former local/trusted admission.  Ignore it without penalizing
            // the relay that returned it in a correlated NODES response.
            return PeerRecordInsertStatus::stale;
        }
        if (stored == PeerRecordStoreStatus::quota_exceeded) {
            // Local durable capacity is not attributable to the sender or a
            // third-party relay.  Treat it like a full routing bucket.
            return PeerRecordInsertStatus::bucket_full;
        }
        const PeerRecordInsertStatus status = directory_.insert_verified(record, now, admission);
        if (status == PeerRecordInsertStatus::inserted ||
            status == PeerRecordInsertStatus::updated) {
            // Backoff is identity-scoped and deliberately survives sequence,
            // TTL, capability and endpoint churn.  Every field is controlled
            // by the signing peer, so resetting on an update would let one key
            // force attacker-paced SOCKS connection attempts.
            discovery_changed_.notify_all();
        } else {
            throw Error("peer directory changed during serialized admission");
        }
        return status;
    }

    void send_discovery_intro(const std::shared_ptr<Link> &link) {
        if (!link_can_use_discovery(link)) {
            return;
        }
        std::optional<PeerRecord> self;
        Hash target{};
        {
            std::lock_guard lock(discovery_mutex_);
            self = self_record_;
            target = directory_.local_node_id();
        }
        if (self && self->expires_at > unix_time_seconds()) {
            link->send(FrameType::peer_record, self->serialize());
        }
        static_cast<void>(link->send_find_nodes(target));
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
            IngestResult result = node_.ingest_peer(std::move(event), link->peer_identity());
            if (result.status == IngestStatus::rejected) {
                throw Error("peer event was rejected");
            }
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
        case FrameType::peer_record: {
            if (!link_can_use_discovery(link)) {
                throw Error("peer is not permitted to use discovery");
            }
            const PeerRecord record = PeerRecord::deserialize(payload);
            if (record.identity != link->peer_identity()) {
                throw Error("peer announced a record for another identity");
            }
            if (admit_peer_record(record) == PeerRecordInsertStatus::equivocation) {
                throw Error("peer equivocated in its self-announced record");
            }
            break;
        }
        case FrameType::find_nodes: {
            if (!link_can_use_discovery(link)) {
                throw Error("peer is not permitted to use discovery");
            }
            const auto [request_id, target] = decode_find_nodes(payload);
            const std::vector<PeerRecord> records = closest_discovery_records(target);
            link->send(FrameType::nodes, encode_peer_records(request_id, records));
            break;
        }
        case FrameType::nodes: {
            if (!link_can_use_discovery(link)) {
                throw Error("peer is not permitted to use discovery");
            }
            auto [request_id, records] = decode_peer_records(payload);
            if (!link->consume_discovery_response(request_id)) {
                throw Error("peer sent an unsolicited or expired NODES response");
            }
            for (const PeerRecord &record : records) {
                const bool third_party = record.identity != link->peer_identity();
                const PeerRecordInsertStatus status = admit_peer_record(record, third_party);
                if (status == PeerRecordInsertStatus::equivocation &&
                    record.identity == link->peer_identity()) {
                    throw Error("peer equivocated in its relayed self record");
                }
            }
            break;
        }
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
    PeerLimits limits_;
    crypto::Identity identity_;
    std::vector<PublicKey> trusted_peer_keys_;
    bool allow_unknown_inbound_ = false;
    bool allow_unknown_outbound_ = false;
    PeerDiscoveryOptions discovery_;
    std::optional<HostPort> tor_proxy_;
    PeerDirectory directory_;
    std::optional<PeerRecord> self_record_;
    std::mutex discovery_mutex_;
    std::condition_variable discovery_changed_;
    std::unordered_set<PublicKey, HashHasher> active_discovery_dials_;
    std::unordered_map<PublicKey, DiscoveryBackoff, HashHasher> discovery_backoff_;
    DiscoveryBackoff discovery_overflow_backoff_;
    std::counting_semaphore<256> discovery_verification_slots_{2};
    std::shared_ptr<TrafficBudget> global_ingress_;
    std::shared_ptr<TrafficBudget> global_egress_;
    std::shared_ptr<HandshakeBudget> global_handshake_budget_;
    std::atomic<bool> running_{false};
    Socket listener_;
    std::thread accept_thread_;
    std::vector<std::thread> connector_threads_;
    std::vector<std::thread> discovery_workers_;
    std::thread discovery_maintenance_thread_;
    std::mutex sessions_mutex_;
    std::condition_variable sessions_changed_;
    std::size_t active_sessions_ = 0;
    std::size_t inbound_sessions_ = 0;
    std::size_t inbound_handshakes_ = 0;
    std::size_t discovery_sessions_ = 0;
    std::size_t untrusted_discovery_sessions_ = 0;
    std::unordered_map<std::string, std::size_t> preauth_by_source_;
    std::unordered_map<PublicKey, std::size_t, HashHasher> inbound_handshakes_by_identity_;
    std::mutex peer_budgets_mutex_;
    std::unordered_map<PublicKey, PeerBudgetEntry, HashHasher> peer_budgets_;
    mutable std::mutex links_mutex_;
    std::vector<std::shared_ptr<Link>> links_;
};

PeerNetwork::PeerNetwork(Node &node, std::optional<HostPort> listen,
                         std::vector<PeerEndpoint> peers, PeerLimits limits,
                         const std::optional<Key> &identity_seed,
                         std::vector<PublicKey> trusted_peer_keys, bool allow_unknown_inbound,
                         bool allow_unknown_outbound, PeerDiscoveryOptions discovery,
                         std::optional<HostPort> tor_proxy)
    : impl_(std::make_unique<Impl>(node, std::move(listen), std::move(peers), limits, identity_seed,
                                   std::move(trusted_peer_keys), allow_unknown_inbound,
                                   allow_unknown_outbound, std::move(discovery),
                                   std::move(tor_proxy))) {}

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
