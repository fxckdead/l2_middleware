#pragma once

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <functional>
#include <chrono>
#include <boost/asio.hpp>

#include "client_connection.hpp"
#include "rsa_manager.hpp"

// Forward declarations
class ClientConnection;

// Connection statistics
struct ConnectionStats
{
    std::atomic<uint32_t> total_connections{0};
    std::atomic<uint32_t> active_connections{0};
    std::atomic<uint32_t> peak_connections{0};
    std::atomic<uint64_t> total_packets_sent{0};
    std::atomic<uint64_t> total_packets_received{0};
    std::atomic<uint64_t> total_bytes_sent{0};
    std::atomic<uint64_t> total_bytes_received{0};
};

class ConnectionManager
{
public:
    using ConnectionPtr = std::shared_ptr<ClientConnection>;
    using ConnectionId = uint32_t;

    // Configuration
    struct Config
    {
        uint32_t max_connections;
        uint32_t rsa_key_pool_size;
        bool enable_connection_logging;
        std::chrono::seconds connection_timeout;

        // Default constructor with default values
        Config()
            : max_connections(1000), rsa_key_pool_size(10), enable_connection_logging(true), connection_timeout(300) // 5 minutes
        {
        }

        // Constructor with custom values
        Config(uint32_t max_conn, uint32_t rsa_keys, bool logging, std::chrono::seconds timeout)
            : max_connections(max_conn), rsa_key_pool_size(rsa_keys), enable_connection_logging(logging), connection_timeout(timeout)
        {
        }
    };

private:
    // Thread-safe connection storage
    mutable std::mutex connections_mutex_;
    std::unordered_map<ConnectionId, ConnectionPtr> active_connections_;
    std::unordered_set<ConnectionId> disconnecting_connections_;

    // Configuration and utilities
    Config config_;
    std::atomic<ConnectionId> next_connection_id_{1};

    // RSA key management
    std::unique_ptr<RSAManager> rsa_manager_;

    // Statistics
    ConnectionStats stats_;

    // IO Context reference
    boost::asio::io_context &io_context_;

public:
    explicit ConnectionManager(boost::asio::io_context &io_context,
                               const Config &config);
    ~ConnectionManager();

    // Connection lifecycle
    ConnectionPtr create_connection(boost::asio::ip::tcp::socket socket);
    bool add_connection(ConnectionPtr connection);
    void remove_connection(ConnectionId connection_id);
    void remove_connection(ClientConnection *connection);

    // Connection queries
    ConnectionPtr get_connection(ConnectionId connection_id) const;
    std::vector<ConnectionPtr> get_all_connections() const;
    std::vector<ConnectionPtr> get_connections_by_state(ClientConnection::State state) const;

    // Connection management
    size_t get_connection_count() const;
    bool is_connection_limit_reached() const;
    void disconnect_all();
    void cleanup_disconnected_connections();

    // Statistics
    const ConnectionStats &get_stats() const { return stats_; }
    void reset_stats();
    void print_stats() const;

    // Configuration
    const Config &get_config() const { return config_; }
    void set_max_connections(uint32_t max_connections);

    // RSA key management
    const ScrambledRSAKeyPair &get_random_rsa_key() const;

    // Packet broadcasting (for future use)
    void broadcast_packet(std::unique_ptr<SendablePacket> packet);
    void broadcast_to_state(std::unique_ptr<SendablePacket> packet, ClientConnection::State state);

private:
    // Internal helpers
    ConnectionId generate_connection_id();
    void handle_connection_disconnect(ClientConnection *connection);
    void update_peak_connections();
    void log_connection_event(const std::string &event) const;

    // Packet handlers for connections
    void setup_connection_handlers(ConnectionPtr connection);
    void handle_packet_from_connection(std::shared_ptr<ReadablePacket> packet, ClientConnection *connection);
    void handle_connection_state_change(ClientConnection *connection, ClientConnection::State old_state, ClientConnection::State new_state);
};

// Utility functions
std::string connection_state_to_string(ClientConnection::State state);
std::string format_bytes(uint64_t bytes);
std::string format_duration(std::chrono::seconds duration);