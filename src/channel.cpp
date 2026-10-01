#include "kairc/channel.hpp"

#include "kairc/codec.hpp"

#include <algorithm>

namespace kairc {

namespace {

void validate_text(std::string_view value, std::size_t maximum, std::string_view label) {
    if (value.empty() || value.size() > maximum) {
        throw Error(std::string(label) + " has an invalid length");
    }
    for (const char raw : value) {
        const auto byte = static_cast<unsigned char>(raw);
        if (byte < 0x20 || byte == 0x7f) {
            throw Error(std::string(label) + " contains a forbidden control byte");
        }
    }
}

Hash payload_aad(const Hash &tag, std::span<const Byte> event_context) {
    return crypto::hash("kairc/channel-aad/v1", {tag, event_context});
}

} // namespace

bool valid_nickname(std::string_view nickname) noexcept {
    if (nickname.empty() || nickname.size() > 24) {
        return false;
    }
    constexpr std::string_view special = "[]\\`_^{|}";
    for (std::size_t index = 0; index < nickname.size(); ++index) {
        const auto byte = static_cast<unsigned char>(nickname[index]);
        const bool letter = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z');
        const bool is_special = special.find(static_cast<char>(byte)) != std::string_view::npos;
        if (index == 0) {
            if (!letter && !is_special) {
                return false;
            }
        } else if (!letter && !is_special && !(byte >= '0' && byte <= '9') && byte != '-') {
            return false;
        }
    }
    return true;
}

Bytes ChatMessage::serialize() const {
    if (!valid_nickname(nickname)) {
        throw Error("nickname is not valid for the IRC boundary");
    }
    validate_text(text, 350, "message");
    Writer writer;
    writer.string(nickname);
    writer.string(text);
    return std::move(writer).take();
}

ChatMessage ChatMessage::deserialize(std::span<const Byte> bytes) {
    Reader reader(bytes);
    ChatMessage message{reader.string(24), reader.string(350)};
    if (!reader.empty()) {
        throw Error("chat message has trailing bytes");
    }
    if (!valid_nickname(message.nickname)) {
        throw Error("nickname is not valid for the IRC boundary");
    }
    validate_text(message.text, 350, "message");
    return message;
}

Channel::~Channel() {
    if (key_) {
        crypto::wipe(*key_);
    }
}

Channel Channel::public_channel(std::string_view name, const Hash &network) {
    Channel channel;
    channel.name_ = canonical_channel(name);
    const auto name_bytes = std::span<const Byte>(
        reinterpret_cast<const Byte *>(channel.name_.data()), channel.name_.size());
    channel.tag_ = crypto::hash("kairc/public-channel/v1", {network, name_bytes});
    return channel;
}

Channel Channel::private_channel(std::string_view name, const Hash &network,
                                 std::span<const Byte> secret) {
    if (secret.size() != 32) {
        throw Error("private channel secret must be exactly 32 bytes");
    }
    Channel channel;
    channel.name_ = canonical_channel(name);
    channel.key_ = crypto::channel_key(secret);
    channel.tag_ = crypto::hash("kairc/private-channel/v1", {network, *channel.key_});
    return channel;
}

std::pair<Nonce, Bytes> Channel::encode(const ChatMessage &message,
                                        std::span<const Byte> event_context) const {
    const Bytes plaintext = message.serialize();
    if (!key_) {
        return {Nonce{}, plaintext};
    }
    if (event_context.empty()) {
        throw Error("private channel payload requires an event context");
    }
    const Nonce nonce = crypto::random_nonce();
    const Hash associated_data = payload_aad(tag_, event_context);
    return {nonce, crypto::encrypt(*key_, nonce, plaintext, associated_data)};
}

std::optional<ChatMessage> Channel::decode(const Nonce &nonce, std::span<const Byte> content,
                                           std::span<const Byte> event_context) const {
    try {
        if (!key_) {
            if (std::any_of(nonce.begin(), nonce.end(), [](Byte value) { return value != 0; })) {
                return std::nullopt;
            }
            return ChatMessage::deserialize(content);
        }
        if (event_context.empty()) {
            return std::nullopt;
        }
        const Hash associated_data = payload_aad(tag_, event_context);
        const auto plaintext = crypto::decrypt(*key_, nonce, content, associated_data);
        if (!plaintext) {
            return std::nullopt;
        }
        return ChatMessage::deserialize(*plaintext);
    } catch (const Error &) {
        return std::nullopt;
    }
}

std::string canonical_channel(std::string_view name) {
    if (name.size() < 2 || name.size() > 64 || name.front() != '#') {
        throw Error("channel names must start with # and contain 2 to 64 bytes");
    }
    std::string output;
    output.reserve(name.size());
    for (const char raw : name) {
        const auto byte = static_cast<unsigned char>(raw);
        if (byte <= ' ' || byte == ',' || byte == ':' || byte == 0x7f) {
            throw Error("channel name contains a forbidden byte");
        }
        if (byte >= 'A' && byte <= 'Z') {
            output.push_back(static_cast<char>(byte + ('a' - 'A')));
        } else if (byte == '[') {
            output.push_back('{');
        } else if (byte == ']') {
            output.push_back('}');
        } else if (byte == '\\') {
            output.push_back('|');
        } else if (byte == '^') {
            output.push_back('~');
        } else {
            output.push_back(static_cast<char>(byte));
        }
    }
    return output;
}

} // namespace kairc
