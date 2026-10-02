#include "kairc/crypto.hpp"

#include <sodium.h>

#include <mutex>

namespace kairc::crypto {

void initialize() {
    static std::once_flag once;
    static int result = -1;
    std::call_once(once, [] { result = sodium_init(); });
    if (result < 0) {
        throw Error("libsodium initialization failed");
    }
}

Hash hash(std::string_view domain, std::initializer_list<std::span<const Byte>> parts) {
    initialize();
    crypto_generichash_state state{};
    Hash output{};
    if (crypto_generichash_init(&state, nullptr, 0, output.size()) != 0) {
        throw Error("BLAKE2b initialization failed");
    }
    crypto_generichash_update(&state, reinterpret_cast<const unsigned char *>(domain.data()),
                              domain.size());
    const Byte separator = 0;
    crypto_generichash_update(&state, &separator, 1);
    for (const auto part : parts) {
        crypto_generichash_update(&state, part.data(), part.size());
    }
    crypto_generichash_final(&state, output.data(), output.size());
    return output;
}

Hash hash(std::string_view domain, std::span<const Byte> data) {
    return hash(domain, {data});
}

Hash hash(std::string_view domain, std::string_view data) {
    return hash(domain,
                std::span<const Byte>(reinterpret_cast<const Byte *>(data.data()), data.size()));
}

Identity Identity::generate() {
    initialize();
    Identity identity;
    crypto_sign_keypair(identity.public_key.data(), identity.secret_key.data());
    return identity;
}

Identity Identity::from_seed(const Key &seed) {
    initialize();
    Identity identity;
    if (crypto_sign_seed_keypair(identity.public_key.data(), identity.secret_key.data(),
                                 seed.data()) != 0) {
        throw Error("Ed25519 seed expansion failed");
    }
    return identity;
}

Identity::~Identity() {
    wipe(secret_key);
}

Identity::Identity(Identity &&other) noexcept
    : public_key(other.public_key), secret_key(other.secret_key) {
    wipe(other.secret_key);
}

Identity &Identity::operator=(Identity &&other) noexcept {
    if (this != &other) {
        wipe(secret_key);
        public_key = other.public_key;
        secret_key = other.secret_key;
        wipe(other.secret_key);
    }
    return *this;
}

Signature Identity::sign(std::span<const Byte> message) const {
    Signature signature{};
    unsigned long long size = 0;
    crypto_sign_detached(signature.data(), &size, message.data(), message.size(),
                         secret_key.data());
    if (size != signature.size()) {
        throw Error("Ed25519 returned an unexpected signature length");
    }
    return signature;
}

bool verify(const PublicKey &key, std::span<const Byte> message, const Signature &signature) {
    initialize();
    return crypto_sign_verify_detached(signature.data(), message.data(), message.size(),
                                       key.data()) == 0;
}

bool has_leading_zero_bits(const Hash &digest, std::uint8_t bits) {
    const std::size_t whole_bytes = bits / 8;
    const std::uint8_t remaining = bits % 8;
    for (std::size_t i = 0; i < whole_bytes; ++i) {
        if (digest[i] != 0) {
            return false;
        }
    }
    if (remaining == 0) {
        return true;
    }
    const auto mask = static_cast<std::uint8_t>(0xffU << (8U - remaining));
    return (digest[whole_bytes] & mask) == 0;
}

Key channel_key(std::span<const Byte> secret) {
    return hash("kairc/channel-key/v1", secret);
}

Nonce random_nonce() {
    initialize();
    Nonce nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

Bytes random_bytes(std::size_t size) {
    initialize();
    Bytes output(size);
    randombytes_buf(output.data(), output.size());
    return output;
}

void wipe(std::span<Byte> bytes) noexcept {
    if (!bytes.empty()) {
        sodium_memzero(bytes.data(), bytes.size());
    }
}

Bytes encrypt(const Key &key, const Nonce &nonce, std::span<const Byte> plaintext,
              std::span<const Byte> associated_data) {
    initialize();
    Bytes ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long size = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &size, plaintext.data(), plaintext.size(), associated_data.data(),
            associated_data.size(), nullptr, nonce.data(), key.data()) != 0) {
        throw Error("XChaCha20-Poly1305 encryption failed");
    }
    ciphertext.resize(size);
    return ciphertext;
}

std::optional<Bytes> decrypt(const Key &key, const Nonce &nonce, std::span<const Byte> ciphertext,
                             std::span<const Byte> associated_data) {
    initialize();
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return std::nullopt;
    }
    Bytes plaintext(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long size = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &size, nullptr, ciphertext.data(), ciphertext.size(),
            associated_data.data(), associated_data.size(), nonce.data(), key.data()) != 0) {
        return std::nullopt;
    }
    plaintext.resize(size);
    return plaintext;
}

} // namespace kairc::crypto
