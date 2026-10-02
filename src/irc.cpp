#include "kairc/irc.hpp"

#include "kairc/node.hpp"
#include "kairc/socket.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <ctime>
#include <deque>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>

namespace kairc {

namespace {

constexpr std::size_t kMaximumIrcPayload = 510;
constexpr std::size_t kMaximumLocalClients = 32;
constexpr std::size_t kMaximumChannelsPerClient = 64;

std::string upper_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char byte) { return static_cast<char>(std::toupper(byte)); });
    return value;
}

std::string fold_irc(std::string_view value) {
    std::string output;
    output.reserve(value.size());
    for (const char raw : value) {
        const auto byte = static_cast<unsigned char>(raw);
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

std::string wire(std::string_view prefix, std::string_view command,
                 std::initializer_list<std::string_view> parameters) {
    std::string output;
    if (!prefix.empty()) {
        output += ':';
        output += prefix;
        output += ' ';
    }
    output += command;
    std::size_t index = 0;
    for (const std::string_view parameter : parameters) {
        output += ' ';
        ++index;
        if (index == parameters.size() && (parameter.empty() || parameter.front() == ':' ||
                                           parameter.find(' ') != std::string_view::npos)) {
            output += ':';
        }
        output += parameter;
    }
    if (output.size() > kMaximumIrcPayload || output.find_first_of("\r\n") != std::string::npos ||
        output.find('\0') != std::string::npos) {
        return {};
    }
    output += "\r\n";
    return output;
}

std::string tagged_wire(std::string_view tags, std::string_view prefix, std::string_view command,
                        std::initializer_list<std::string_view> parameters) {
    std::string plain = wire(prefix, command, parameters);
    if (plain.empty() || tags.empty()) {
        return plain;
    }
    if (tags.find_first_of(" \r\n") != std::string_view::npos ||
        tags.find('\0') != std::string_view::npos) {
        return {};
    }
    std::string output = "@" + std::string(tags) + " " + plain;
    if (output.size() > kMaximumIrcPayload + 2) {
        return {};
    }
    return output;
}

std::string irc_timestamp(std::uint64_t timestamp_ms) {
    const std::time_t seconds = static_cast<std::time_t>(timestamp_ms / 1'000ULL);
    std::tm broken_down{};
    if (gmtime_r(&seconds, &broken_down) == nullptr) {
        return {};
    }
    char date[32]{};
    if (std::strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &broken_down) == 0) {
        return {};
    }
    char output[40]{};
    const int written = std::snprintf(output, sizeof(output), "%s.%03uZ", date,
                                      static_cast<unsigned int>(timestamp_ms % 1'000ULL));
    if (written <= 0 || static_cast<std::size_t>(written) >= sizeof(output)) {
        return {};
    }
    return output;
}

std::vector<std::string> split_spaces(std::string_view value) {
    std::vector<std::string> output;
    while (!value.empty()) {
        while (!value.empty() && value.front() == ' ') {
            value.remove_prefix(1);
        }
        if (value.empty()) {
            break;
        }
        const auto space = value.find(' ');
        output.emplace_back(value.substr(0, space));
        if (space == std::string_view::npos) {
            break;
        }
        value.remove_prefix(space + 1);
    }
    return output;
}

std::vector<std::string> split_comma(std::string_view value) {
    std::vector<std::string> output;
    while (!value.empty()) {
        const auto comma = value.find(',');
        output.emplace_back(value.substr(0, comma));
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return output;
}

} // namespace

IrcCommand parse_irc_line(std::string_view line) {
    if (line.empty() || line.size() > kMaximumIrcPayload ||
        line.find_first_of("\r\n") != std::string_view::npos ||
        line.find('\0') != std::string_view::npos) {
        throw Error("invalid IRC line");
    }
    while (!line.empty() && line.front() == ' ') {
        line.remove_prefix(1);
    }
    if (line.empty() || line.front() == ':') {
        throw Error("client IRC line has no valid command");
    }
    const auto space = line.find(' ');
    IrcCommand command;
    command.name = upper_ascii(std::string(line.substr(0, space)));
    if (space == std::string_view::npos) {
        return command;
    }
    line.remove_prefix(space + 1);
    while (!line.empty()) {
        while (!line.empty() && line.front() == ' ') {
            line.remove_prefix(1);
        }
        if (line.empty()) {
            break;
        }
        if (line.front() == ':') {
            command.parameters.emplace_back(line.substr(1));
            break;
        }
        const auto next = line.find(' ');
        command.parameters.emplace_back(line.substr(0, next));
        if (next == std::string_view::npos) {
            break;
        }
        line.remove_prefix(next + 1);
        if (command.parameters.size() >= 15) {
            throw Error("IRC line has too many parameters");
        }
    }
    return command;
}

class IrcGateway::Impl {
    struct Client {
        explicit Client(Socket accepted_socket) : socket(std::move(accepted_socket)) {}

        void send(std::string line) {
            if (line.empty() || !alive.load()) {
                return;
            }
            std::lock_guard lock(write_mutex);
            try {
                socket.send_all(std::span<const Byte>(reinterpret_cast<const Byte *>(line.data()),
                                                      line.size()));
            } catch (const Error &) {
                alive.store(false);
                socket.close();
            }
        }

        std::string prefix() const {
            std::lock_guard lock(state_mutex);
            return prefix_locked();
        }

        std::string prefix_locked() const {
            return nickname + "!anon@local.kairc";
        }

        bool reserve_message_slot() {
            const auto now = std::chrono::steady_clock::now();
            const auto cutoff = now - std::chrono::seconds(2);
            std::lock_guard lock(state_mutex);
            while (!recent_messages.empty() && recent_messages.front() < cutoff) {
                recent_messages.pop_front();
            }
            if (recent_messages.size() >= 8) {
                return false;
            }
            recent_messages.push_back(now);
            return true;
        }

        Socket socket;
        std::mutex write_mutex;
        mutable std::mutex state_mutex;
        std::string nickname;
        bool user_received = false;
        bool registered = false;
        bool cap_negotiating = false;
        bool message_tags = false;
        bool server_time = false;
        bool batch = false;
        std::set<std::string> channels;
        std::deque<std::chrono::steady_clock::time_point> recent_messages;
        std::atomic<bool> alive{true};
    };

  public:
    Impl(Node &node, HostPort listen, std::function<void(const Event &)> event_published)
        : node_(node), listen_(std::move(listen)), event_published_(std::move(event_published)) {}

    ~Impl() {
        stop();
    }

    void start() {
        if (running_.exchange(true)) {
            return;
        }
        try {
            listener_ = Socket::listen_tcp(listen_);
            accept_thread_ = std::thread([this] { accept_loop(); });
        } catch (...) {
            running_.store(false);
            throw;
        }
    }

    void stop() {
        if (!running_.exchange(false)) {
            return;
        }
        listener_.close();
        {
            std::lock_guard lock(clients_mutex_);
            for (const auto &client : clients_) {
                client->alive.store(false);
                client->socket.close();
            }
        }
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
        {
            std::unique_lock lock(active_mutex_);
            active_changed_.wait(lock, [this] { return active_clients_.load() == 0; });
        }
        std::lock_guard lock(clients_mutex_);
        clients_.clear();
    }

    void deliver(const DeliveredMessage &message, const Client *excluded = nullptr) {
        std::vector<std::shared_ptr<Client>> clients;
        {
            std::lock_guard lock(clients_mutex_);
            clients = clients_;
        }
        for (const auto &client : clients) {
            if (client.get() == excluded || !client->alive.load()) {
                continue;
            }
            bool joined = false;
            {
                std::lock_guard lock(client->state_mutex);
                joined = client->registered && client->channels.contains(message.channel);
            }
            if (joined) {
                send_message(client, message);
            }
        }
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
                socket.set_send_timeout(2);
                auto client = std::make_shared<Client>(std::move(socket));
                {
                    std::lock_guard lock(clients_mutex_);
                    if (clients_.size() >= kMaximumLocalClients) {
                        client->send("ERROR :Local IRC client limit reached\r\n");
                        client->socket.close();
                        continue;
                    }
                    clients_.push_back(client);
                }
                active_clients_.fetch_add(1);
                try {
                    std::thread([this, client] {
                        try {
                            client_loop(client);
                        } catch (...) {
                            client->alive.store(false);
                            client->socket.close();
                            std::lock_guard clients_lock(clients_mutex_);
                            std::erase(clients_, client);
                        }
                        std::lock_guard lock(active_mutex_);
                        active_clients_.fetch_sub(1);
                        active_changed_.notify_all();
                    }).detach();
                } catch (...) {
                    {
                        std::lock_guard lock(active_mutex_);
                        active_clients_.fetch_sub(1);
                    }
                    client->alive.store(false);
                    client->socket.close();
                    {
                        std::lock_guard lock(clients_mutex_);
                        std::erase(clients_, client);
                    }
                    active_changed_.notify_all();
                    throw;
                }
            } catch (const std::exception &) {
                if (running_.load()) {
                    std::cerr << "kaircd: local IRC accept failed\n";
                }
            }
        }
    }

    void client_loop(const std::shared_ptr<Client> &client) {
        try {
            while (running_.load() && client->alive.load()) {
                // Include the optional CR byte while retaining IRC's 510-byte
                // payload limit (512 bytes on the wire with CRLF).
                const auto line = client->socket.receive_line(kMaximumIrcPayload + 1);
                if (!line) {
                    break;
                }
                try {
                    if (!handle(client, parse_irc_line(*line))) {
                        break;
                    }
                } catch (const Error &exception) {
                    numeric(client, 417, {"Input error", exception.what()});
                }
            }
        } catch (...) {
            client->alive.store(false);
        }
        disconnect(client, "Client disconnected");
    }

    bool handle(const std::shared_ptr<Client> &client, const IrcCommand &command) {
        if (command.name == "CAP") {
            if (command.parameters.empty()) {
                return true;
            }
            const std::string subcommand = upper_ascii(command.parameters[0]);
            if (subcommand == "LS") {
                {
                    std::lock_guard lock(client->state_mutex);
                    client->cap_negotiating = true;
                }
                client->send(wire("kairc.local", "CAP",
                                  {nick_or_star(client), "LS", "message-tags server-time batch"}));
            } else if (subcommand == "REQ") {
                const std::string request =
                    command.parameters.size() > 1 ? command.parameters.back() : "";
                bool supported = !request.empty();
                const auto capabilities = split_spaces(request);
                for (const std::string &raw : capabilities) {
                    const std::string_view name = raw.starts_with('-')
                                                      ? std::string_view(raw).substr(1)
                                                      : std::string_view(raw);
                    if (name != "message-tags" && name != "server-time" && name != "batch") {
                        supported = false;
                    }
                }
                if (!supported) {
                    client->send(
                        wire("kairc.local", "CAP", {nick_or_star(client), "NAK", request}));
                } else {
                    std::lock_guard lock(client->state_mutex);
                    for (const std::string &raw : capabilities) {
                        const bool enabled = !raw.starts_with('-');
                        const std::string_view name =
                            enabled ? std::string_view(raw) : std::string_view(raw).substr(1);
                        if (name == "message-tags") {
                            client->message_tags = enabled;
                        } else if (name == "server-time") {
                            client->server_time = enabled;
                        } else if (name == "batch") {
                            client->batch = enabled;
                        }
                    }
                    client->send(
                        wire("kairc.local", "CAP",
                             {client->nickname.empty() ? "*" : client->nickname, "ACK", request}));
                }
            } else if (subcommand == "END") {
                {
                    std::lock_guard lock(client->state_mutex);
                    client->cap_negotiating = false;
                }
                maybe_register(client);
            }
            return true;
        }
        if (command.name == "NICK") {
            if (command.parameters.empty() || !valid_nickname(command.parameters[0])) {
                numeric(client, 432,
                        {command.parameters.empty() ? "*" : command.parameters[0],
                         "Erroneous nickname"});
                return true;
            }
            const std::string nickname = command.parameters[0];
            const std::string folded_nickname = fold_irc(nickname);
            bool collision = false;
            std::string old_prefix;
            bool was_registered = false;
            {
                std::lock_guard lock(clients_mutex_);
                for (const auto &other : clients_) {
                    if (other != client) {
                        std::lock_guard state(other->state_mutex);
                        if (!other->nickname.empty() &&
                            fold_irc(other->nickname) == folded_nickname) {
                            collision = true;
                            break;
                        }
                    }
                }
                if (!collision) {
                    std::lock_guard state(client->state_mutex);
                    old_prefix = client->prefix_locked();
                    was_registered = client->registered;
                    client->nickname = nickname;
                }
            }
            if (collision) {
                numeric(client, 433, {nickname, "Nickname is already in use locally"});
                return true;
            }
            if (was_registered) {
                broadcast_shared(client, wire(old_prefix, "NICK", {nickname}), true);
            } else {
                maybe_register(client);
            }
            return true;
        }
        if (command.name == "USER") {
            if (command.parameters.size() < 4) {
                numeric(client, 461, {"USER", "Not enough parameters"});
                return true;
            }
            {
                std::lock_guard lock(client->state_mutex);
                client->user_received = true;
            }
            maybe_register(client);
            return true;
        }
        if (command.name == "PING") {
            if (!command.parameters.empty()) {
                client->send(
                    wire("kairc.local", "PONG", {"kairc.local", command.parameters.back()}));
            }
            return true;
        }
        if (command.name == "PONG" || command.name == "PASS") {
            return true;
        }
        if (command.name == "QUIT") {
            return false;
        }
        bool registered = false;
        {
            std::lock_guard lock(client->state_mutex);
            registered = client->registered;
        }
        if (!registered) {
            numeric(client, 451, {"You have not registered"});
            return true;
        }
        if (command.name == "JOIN") {
            handle_join(client, command.parameters);
        } else if (command.name == "PART") {
            handle_part(client, command.parameters);
        } else if (command.name == "PRIVMSG" || command.name == "NOTICE") {
            handle_message(client, command.name, command.parameters);
        } else if (command.name == "NAMES") {
            if (!command.parameters.empty()) {
                send_names(client, canonical_channel(command.parameters[0]));
            }
        } else if (command.name == "MODE") {
            if (!command.parameters.empty() && command.parameters[0].starts_with('#')) {
                numeric(client, 324, {canonical_channel(command.parameters[0]), "+n"});
            } else {
                numeric(client, 221, {"+"});
            }
        } else if (command.name == "WHOIS") {
            const std::string target =
                command.parameters.empty() ? nick_or_star(client) : command.parameters.back();
            numeric(client, 311, {target, "anon", "p2p.kairc", "*", "anonymous pseudonym"});
            numeric(client, 318, {target, "End of /WHOIS list"});
        } else {
            numeric(client, 421, {command.name, "Unknown command"});
        }
        return true;
    }

    void maybe_register(const std::shared_ptr<Client> &client) {
        std::string nickname;
        {
            std::lock_guard lock(client->state_mutex);
            if (client->registered || client->nickname.empty() || !client->user_received ||
                client->cap_negotiating) {
                return;
            }
            client->registered = true;
            nickname = client->nickname;
        }
        numeric(client, 1, {"Welcome to Kairc, " + nickname + ". No account was created."});
        numeric(client, 2, {"Your IRC connection stays on this machine; events travel over P2P."});
        numeric(client, 4, {"kairc.local", "Kairc-0.4.0-dev", "", "n"});
        numeric(
            client, 5,
            {"CHANTYPES=#", "CASEMAPPING=rfc1459", "NICKLEN=24", "NETWORK=Kairc", "are supported"});
        numeric(client, 375, {"- Kairc privacy notice -"});
        numeric(client, 372, {"- Nicknames are pseudonyms, not verified identities."});
        numeric(client, 372,
                {"- Public channels are public; configured private channels are encrypted."});
        numeric(client, 376, {"End of /MOTD"});
    }

    void handle_join(const std::shared_ptr<Client> &client,
                     const std::vector<std::string> &parameters) {
        if (parameters.empty()) {
            numeric(client, 461, {"JOIN", "Not enough parameters"});
            return;
        }
        for (const std::string &requested : split_comma(parameters[0])) {
            const std::string channel = canonical_channel(requested);
            bool at_limit = false;
            {
                std::lock_guard lock(client->state_mutex);
                if (client->channels.contains(channel)) {
                    continue;
                }
                at_limit = client->channels.size() >= kMaximumChannelsPerClient;
            }
            if (at_limit) {
                numeric(client, 405, {channel, "You have joined too many local channels"});
                continue;
            }
            node_.register_public_channel(channel);
            {
                std::lock_guard lock(client->state_mutex);
                client->channels.insert(channel);
            }
            broadcast_channel(channel, wire(client->prefix(), "JOIN", {channel}));
            const std::string privacy =
                node_.channel_is_encrypted(channel)
                    ? "Encrypted shared-secret channel; membership and timing metadata remain "
                      "visible."
                    : "Public channel; messages are readable by every relaying node.";
            numeric(client, 332, {channel, privacy});
            send_names(client, channel);
            send_history(client, channel);
        }
    }

    void handle_part(const std::shared_ptr<Client> &client,
                     const std::vector<std::string> &parameters) {
        if (parameters.empty()) {
            numeric(client, 461, {"PART", "Not enough parameters"});
            return;
        }
        const std::string reason = parameters.size() > 1 ? parameters[1] : "Leaving";
        for (const std::string &requested : split_comma(parameters[0])) {
            const std::string channel = canonical_channel(requested);
            bool joined = false;
            {
                std::lock_guard lock(client->state_mutex);
                joined = client->channels.contains(channel);
            }
            if (!joined) {
                numeric(client, 442, {channel, "You're not on that channel"});
                continue;
            }
            broadcast_channel(channel, wire(client->prefix(), "PART", {channel, reason}));
            std::lock_guard lock(client->state_mutex);
            client->channels.erase(channel);
        }
    }

    void handle_message(const std::shared_ptr<Client> &client, std::string_view command,
                        const std::vector<std::string> &parameters) {
        const bool notice = command == "NOTICE";
        if (parameters.size() < 2 || parameters[0].empty() || parameters[1].empty()) {
            if (!notice) {
                numeric(client, 461, {"PRIVMSG", "Not enough parameters"});
            }
            return;
        }
        if (!parameters[0].starts_with('#')) {
            if (!notice) {
                numeric(client, 401,
                        {parameters[0], "Encrypted direct messages are not implemented yet"});
            }
            return;
        }
        const std::string channel = canonical_channel(parameters[0]);
        bool joined = false;
        {
            std::lock_guard lock(client->state_mutex);
            joined = client->channels.contains(channel);
        }
        if (!joined) {
            if (!notice) {
                numeric(client, 404, {channel, "Cannot send to channel"});
            }
            return;
        }
        if (notice) {
            return; // NOTICE is never turned into a durable event in v0.2.
        }
        if (!client->reserve_message_slot()) {
            numeric(client, 439, {channel, "Local anonymous publish rate exceeded"});
            return;
        }
        try {
            std::string nickname;
            {
                std::lock_guard lock(client->state_mutex);
                nickname = client->nickname;
            }
            Event event = node_.publish(channel, nickname, parameters[1], false);
            deliver(DeliveredMessage{event.id, event.timestamp_ms, channel, nickname, parameters[1],
                                     node_.channel_is_encrypted(channel)},
                    client.get());
            if (event_published_) {
                event_published_(event);
            }
        } catch (const Error &exception) {
            numeric(client, 439, {channel, exception.what()});
        }
    }

    std::string next_batch_id() {
        return "kairc" + std::to_string(batch_counter_.fetch_add(1));
    }

    void send_message(const std::shared_ptr<Client> &client, const DeliveredMessage &message,
                      std::string_view batch_id = {}) {
        bool message_tags = false;
        bool server_time = false;
        {
            std::lock_guard lock(client->state_mutex);
            message_tags = client->message_tags;
            server_time = client->server_time;
        }

        std::vector<std::string> tags;
        if (!batch_id.empty()) {
            tags.push_back("batch=" + std::string(batch_id));
        }
        if (server_time) {
            const std::string timestamp = irc_timestamp(message.timestamp_ms);
            if (!timestamp.empty()) {
                tags.push_back("time=" + timestamp);
            }
        }
        if (message.replayed && message_tags) {
            tags.emplace_back("kairc.io/replay=1");
        }

        const auto join_tags = [](const std::vector<std::string> &values) {
            std::string joined;
            for (const std::string &value : values) {
                if (!joined.empty()) {
                    joined += ';';
                }
                joined += value;
            }
            return joined;
        };
        const std::string prefix = message.nickname + "!anon@p2p.kairc";
        std::string line =
            tagged_wire(join_tags(tags), prefix, "PRIVMSG", {message.channel, message.text});
        if (line.empty() && message.replayed && message_tags) {
            std::erase(tags, "kairc.io/replay=1");
            line = tagged_wire(join_tags(tags), prefix, "PRIVMSG", {message.channel, message.text});
        }
        if (line.empty() && !batch_id.empty()) {
            line = tagged_wire("batch=" + std::string(batch_id), prefix, "PRIVMSG",
                               {message.channel, message.text});
        }
        if (line.empty()) {
            line = wire(prefix, "PRIVMSG", {message.channel, message.text});
        }
        const bool replay_is_explicit =
            (!batch_id.empty() && line.find("batch=") != std::string::npos) ||
            line.find("kairc.io/replay=1") != std::string::npos || line.starts_with("@time=") ||
            line.find(";time=") != std::string::npos;
        if (message.replayed && !replay_is_explicit) {
            client->send(
                wire("kairc.local", "NOTICE",
                     {message.channel, "Delayed event follows; this client did not negotiate "
                                       "a replay marker that fits this line."}));
        }
        client->send(std::move(line));
    }

    void send_history(const std::shared_ptr<Client> &client, const std::string &channel) {
        bool supports_batch = false;
        bool supports_timestamped_replay = false;
        {
            std::lock_guard lock(client->state_mutex);
            supports_batch = client->batch;
            supports_timestamped_replay = client->server_time || client->message_tags;
        }
        if (!supports_batch && !supports_timestamped_replay) {
            return;
        }
        const std::vector<DeliveredMessage> history = node_.history(channel, 100);
        if (history.empty()) {
            return;
        }

        std::string batch_id;
        if (supports_batch) {
            batch_id = next_batch_id();
            client->send(wire("kairc.local", "BATCH", {"+" + batch_id, "kairc/replay", channel}));
        } else {
            client->send(
                wire("kairc.local", "NOTICE", {channel, "Replaying canonical local history."}));
        }
        for (const DeliveredMessage &message : history) {
            send_message(client, message, batch_id);
        }
        if (!batch_id.empty()) {
            client->send(wire("kairc.local", "BATCH", {"-" + batch_id}));
        }
    }

    void send_names(const std::shared_ptr<Client> &client, const std::string &channel) {
        std::vector<std::string> names;
        {
            std::lock_guard lock(clients_mutex_);
            for (const auto &member : clients_) {
                std::lock_guard state(member->state_mutex);
                if (member->registered && member->channels.contains(channel)) {
                    names.push_back(member->nickname);
                }
            }
        }
        std::sort(names.begin(), names.end());
        std::string joined;
        for (const std::string &name : names) {
            if (!joined.empty() && joined.size() + 1 + name.size() > 350) {
                numeric(client, 353, {"=", channel, joined});
                joined.clear();
            }
            if (!joined.empty()) {
                joined += ' ';
            }
            joined += name;
        }
        numeric(client, 353, {"=", channel, joined});
        numeric(client, 366, {channel, "End of /NAMES list; only local clients are shown"});
    }

    void numeric(const std::shared_ptr<Client> &client, int code,
                 std::initializer_list<std::string_view> parameters) {
        std::vector<std::string_view> all;
        all.reserve(parameters.size() + 1);
        const std::string nickname = nick_or_star(client);
        all.push_back(nickname);
        all.insert(all.end(), parameters.begin(), parameters.end());

        std::string output = ":kairc.local ";
        if (code < 100) {
            output += '0';
        }
        if (code < 10) {
            output += '0';
        }
        output += std::to_string(code);
        for (std::size_t index = 0; index < all.size(); ++index) {
            output += ' ';
            const auto parameter = all[index];
            if (index + 1 == all.size() && (parameter.empty() || parameter.front() == ':' ||
                                            parameter.find(' ') != std::string_view::npos)) {
                output += ':';
            }
            output += parameter;
        }
        if (output.size() <= kMaximumIrcPayload &&
            output.find_first_of("\r\n") == std::string::npos &&
            output.find('\0') == std::string::npos) {
            output += "\r\n";
            client->send(std::move(output));
        }
    }

    std::string nick_or_star(const std::shared_ptr<Client> &client) const {
        std::lock_guard lock(client->state_mutex);
        return client->nickname.empty() ? "*" : client->nickname;
    }

    void broadcast_channel(const std::string &channel, const std::string &line) {
        std::vector<std::shared_ptr<Client>> clients;
        {
            std::lock_guard lock(clients_mutex_);
            clients = clients_;
        }
        for (const auto &member : clients) {
            bool joined = false;
            {
                std::lock_guard lock(member->state_mutex);
                joined = member->channels.contains(channel);
            }
            if (joined) {
                member->send(line);
            }
        }
    }

    void broadcast_shared(const std::shared_ptr<Client> &source, const std::string &line,
                          bool include_source) {
        std::set<std::string> channels;
        {
            std::lock_guard lock(source->state_mutex);
            channels = source->channels;
        }
        std::vector<std::shared_ptr<Client>> clients;
        {
            std::lock_guard lock(clients_mutex_);
            clients = clients_;
        }
        for (const auto &member : clients) {
            if (!include_source && member == source) {
                continue;
            }
            std::lock_guard state(member->state_mutex);
            bool shared = member == source && include_source;
            for (const std::string &channel : channels) {
                shared = shared || member->channels.contains(channel);
            }
            if (shared) {
                member->send(line);
            }
        }
    }

    void disconnect(const std::shared_ptr<Client> &client, std::string_view reason) {
        const bool announce = client->alive.exchange(false);
        if (announce) {
            const std::string quit = wire(client->prefix(), "QUIT", {reason});
            broadcast_shared(client, quit, false);
        }
        client->socket.close();
        std::lock_guard lock(clients_mutex_);
        std::erase(clients_, client);
    }

    Node &node_;
    HostPort listen_;
    std::function<void(const Event &)> event_published_;
    std::atomic<bool> running_{false};
    Socket listener_;
    std::thread accept_thread_;
    std::mutex clients_mutex_;
    std::vector<std::shared_ptr<Client>> clients_;
    std::atomic<std::size_t> active_clients_{0};
    std::mutex active_mutex_;
    std::condition_variable active_changed_;
    std::atomic<std::uint64_t> batch_counter_{1};
};

IrcGateway::IrcGateway(Node &node, HostPort listen,
                       std::function<void(const Event &)> event_published)
    : impl_(std::make_unique<Impl>(node, std::move(listen), std::move(event_published))) {}

IrcGateway::~IrcGateway() = default;

void IrcGateway::start() {
    impl_->start();
}
void IrcGateway::stop() {
    impl_->stop();
}
void IrcGateway::deliver(const DeliveredMessage &message) {
    impl_->deliver(message);
}

} // namespace kairc
