#pragma once

#include "kairc/types.hpp"

#include <initializer_list>
#include <optional>

namespace kairc::crypto {

void initialize();

Hash hash(std::string_view domain, std::initializer_list<std::span<const Byte>> parts);
Hash hash(std::string_view domain, std::span<const Byte> data);
Hash hash(std::string_view domain, std::string_view data);

struct Identity {
    PublicKey public_key{};
    SecretKey secret_key{};

    Identity() = default;
    ~Identity();

    Identity(const Identity &) = delete;
    Identity &operator=(const Identity &) = delete;
    Identity(Identity &&other) noexcept;
    Identity &operator=(Identity &&other) noexcept;

    static Identity generate();
    static Identity from_seed(const Key &seed);
    Signature sign(std::span<const Byte> message) const;
};

bool verify(const PublicKey &key, std::span<const Byte> message, const Signature &signature);
bool has_leading_zero_bits(const Hash &digest, std::uint8_t bits);

Key channel_key(std::span<const Byte> secret);
Nonce random_nonce();
Bytes random_bytes(std::size_t size);
void wipe(std::span<Byte> bytes) noexcept;

Bytes encrypt(const Key &key, const Nonce &nonce, std::span<const Byte> plaintext,
              std::span<const Byte> associated_data);
std::optional<Bytes> decrypt(const Key &key, const Nonce &nonce, std::span<const Byte> ciphertext,
                             std::span<const Byte> associated_data);

} // namespace kairc::crypto
