#pragma once

#include "kairc/config.hpp"

#include <functional>
#include <memory>

namespace kairc {

class Node;

struct IrcCommand {
    std::string name;
    std::vector<std::string> parameters;
};

IrcCommand parse_irc_line(std::string_view line);

class IrcGateway {
  public:
    IrcGateway(Node &node, HostPort listen, std::function<void(const Event &)> event_published);
    ~IrcGateway();

    IrcGateway(const IrcGateway &) = delete;
    IrcGateway &operator=(const IrcGateway &) = delete;

    void start();
    void stop();
    void deliver(const DeliveredMessage &message);

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace kairc
