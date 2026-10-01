#include "kairc/config.hpp"
#include "kairc/crypto.hpp"
#include "kairc/irc.hpp"
#include "kairc/node.hpp"
#include "kairc/p2p.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <thread>

namespace {

std::atomic<bool> running{true};

void stop_signal(int) {
    running.store(false);
}

void usage() {
    std::cout << "Usage: kaircd [--config PATH] [--check-config]\n"
                 "       kaircd --gen-channel-secret\n"
                 "       kaircd --version\n";
}

} // namespace

int main(int argc, char **argv) {
    try {
        std::filesystem::path config_path = "kairc.conf";
        bool explicit_config = false;
        bool check_config = false;

        for (int index = 1; index < argc; ++index) {
            const std::string argument = argv[index];
            if (argument == "--config" && index + 1 < argc) {
                config_path = argv[++index];
                explicit_config = true;
            } else if (argument == "--check-config") {
                check_config = true;
            } else if (argument == "--gen-channel-secret") {
                kairc::crypto::initialize();
                std::cout << kairc::hex(kairc::crypto::random_bytes(32)) << '\n';
                return 0;
            } else if (argument == "--version") {
                std::cout << "kaircd 0.2.0-dev (C++ event-graph prototype)\n";
                return 0;
            } else if (argument == "--help" || argument == "-h") {
                usage();
                return 0;
            } else {
                usage();
                throw kairc::Error("unknown or incomplete command-line option: " + argument);
            }
        }

        kairc::crypto::initialize();
        kairc::Config config;
        if (explicit_config || std::filesystem::exists(config_path)) {
            config = kairc::Config::load(config_path);
        } else {
            config.finalize();
        }
        if (check_config) {
            std::cout << "configuration is valid\n";
            return 0;
        }

        kairc::Node node(config.database, config.node);
        for (kairc::ChannelConfig &channel : config.channels) {
            if (channel.secret) {
                node.register_private_channel(channel.name, *channel.secret);
                kairc::crypto::wipe(*channel.secret);
                channel.secret.reset();
            } else {
                node.register_public_channel(channel.name);
            }
        }

        kairc::PeerNetwork peers(node, config.p2p_listen, config.peers);
        kairc::IrcGateway gateway(node, config.irc_listen,
                                  [&peers](const kairc::Event &event) { peers.broadcast(event); });
        node.set_message_handler(
            [&gateway](const kairc::DeliveredMessage &message) { gateway.deliver(message); });

        std::signal(SIGINT, stop_signal);
        std::signal(SIGTERM, stop_signal);
        peers.start();
        gateway.start();
        std::cout << "kaircd: local IRC gateway ready on " << config.irc_listen.host << ':'
                  << config.irc_listen.port << '\n';
        std::cout << "kaircd: ephemeral node identity; " << config.node.retention_hours
                  << " hourly DAG(s) retained\n";

        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            node.maintain();
        }
        gateway.stop();
        peers.stop();
        return 0;
    } catch (const std::exception &exception) {
        std::cerr << "kaircd: " << exception.what() << '\n';
        return 1;
    }
}
