#pragma once

#include "kairc/crypto.hpp"

#include <optional>

namespace kairc {

struct ChatMessage {
    std::string nickname;
    std::string text;

    Bytes serialize() const;
    static ChatMessage deserialize(std::span<const Byte> bytes);
};

bool valid_nickname(std::string_view nickname) noexcept;

class Channel {
  public:
    Channel() = default;
    ~Channel();
    Channel(const Channel &) = default;
    Channel &operator=(const Channel &) = default;
    Channel(Channel &&) noexcept = default;
    Channel &operator=(Channel &&) noexcept = default;

    static Channel public_channel(std::string_view name, const Hash &network);
    static Channel private_channel(std::string_view name, const Hash &network,
                                   std::span<const Byte> secret);

    const std::string &name() const noexcept {
        return name_;
    }
    const Hash &tag() const noexcept {
        return tag_;
    }
    bool encrypted() const noexcept {
        return key_.has_value();
    }

    std::pair<Nonce, Bytes> encode(const ChatMessage &message,
                                   std::span<const Byte> event_context) const;
    std::optional<ChatMessage> decode(const Nonce &nonce, std::span<const Byte> content,
                                      std::span<const Byte> event_context) const;

  private:
    std::string name_;
    Hash tag_{};
    std::optional<Key> key_;
};

std::string canonical_channel(std::string_view name);

} // namespace kairc
