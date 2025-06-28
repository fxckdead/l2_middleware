#include "base_connection_manager.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <random>
#include <ctime>

// =============================================================================
// Constructor and Destructor
// =============================================================================

BaseConnectionManager::BaseConnectionManager(boost::asio::io_context &io_context, const Config &config)
    : config_(config), io_context_(io_context)
{
    // Initialize RSA key manager with configured pool size
    rsa_manager_ = std::make_unique<RSAManager>(config_.rsa_key_pool_size);

    log_connection_event("BaseConnectionManager initialized with max " +
                         std::to_string(config_.max_connections) + " connections");
}

BaseConnectionManager::~BaseConnectionManager()
{
    disconnect_all();
    log_connection_event("BaseConnectionManager destroyed");
}

// =============================================================================
// Connection Lifecycle
// =============================================================================

bool BaseConnectionManager::add_connection(ConnectionPtr connection)
{
    if (!connection || is_connection_limit_reached())
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(connections_mutex_);

    ConnectionId id = generate_connection_id();
    active_connections_[id] = connection;

    // Update statistics
    stats_.total_connections.fetch_add(1);
    stats_.active_connections.fetch_add(1);
    update_peak_connections();

    log_connection_event("Added connection " + std::to_string(id) +
                         " (" + connection->get_remote_address() + ")");

    // Initialize the connection (derived class handles this)
    initialize_connection(connection);

    return true;
}

void BaseConnectionManager::remove_connection(ConnectionId connection_id)
{
    ConnectionPtr connection;

    {
        std::lock_guard<std::mutex> lock(connections_mutex_);

        auto it = active_connections_.find(connection_id);
        if (it != active_connections_.end())
        {
            connection = it->second;
            active_connections_.erase(it);
            disconnecting_connections_.insert(connection_id);
        }
    }

    if (connection)
    {
        // Update statistics
        stats_.active_connections.fetch_sub(1);

        log_connection_event("Removed connection " + std::to_string(connection_id) +
                             " (" + connection->get_remote_address() + ")");

        // Disconnect the connection
        connection->disconnect();
    }
}

void BaseConnectionManager::remove_connection(BaseClientConnection *connection)
{
    if (!connection)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(connections_mutex_);

    for (auto it = active_connections_.begin(); it != active_connections_.end(); ++it)
    {
        if (it->second.get() == connection)
        {
            ConnectionId id = it->first;
            active_connections_.erase(it);
            disconnecting_connections_.insert(id);

            // Update statistics
            stats_.active_connections.fetch_sub(1);

            log_connection_event("Removed connection by pointer (" +
                                 connection->get_remote_address() + ")");
            break;
        }
    }
}

// =============================================================================
// Connection Queries
// =============================================================================

BaseConnectionManager::ConnectionPtr BaseConnectionManager::get_connection(ConnectionId connection_id) const
{
    std::lock_guard<std::mutex> lock(connections_mutex_);

    auto it = active_connections_.find(connection_id);
    return (it != active_connections_.end()) ? it->second : nullptr;
}

std::vector<BaseConnectionManager::ConnectionPtr> BaseConnectionManager::get_all_connections() const
{
    std::lock_guard<std::mutex> lock(connections_mutex_);

    std::vector<ConnectionPtr> connections;
    connections.reserve(active_connections_.size());

    for (const auto &pair : active_connections_)
    {
        connections.push_back(pair.second);
    }

    return connections;
}

std::vector<BaseConnectionManager::ConnectionPtr> BaseConnectionManager::get_connections_by_state(BaseClientConnection::State state) const
{
    std::lock_guard<std::mutex> lock(connections_mutex_);

    std::vector<ConnectionPtr> connections;

    for (const auto &pair : active_connections_)
    {
        if (pair.second->get_state() == state)
        {
            connections.push_back(pair.second);
        }
    }

    return connections;
}

// =============================================================================
// Connection Management
// =============================================================================

size_t BaseConnectionManager::get_connection_count() const
{
    std::lock_guard<std::mutex> lock(connections_mutex_);
    return active_connections_.size();
}

bool BaseConnectionManager::is_connection_limit_reached() const
{
    return get_connection_count() >= config_.max_connections;
}

void BaseConnectionManager::disconnect_all()
{
    std::vector<ConnectionPtr> connections;

    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections.reserve(active_connections_.size());

        for (const auto &pair : active_connections_)
        {
            connections.push_back(pair.second);
        }

        active_connections_.clear();
        disconnecting_connections_.clear();
    }

    // Disconnect all connections outside the lock
    for (auto &connection : connections)
    {
        connection->force_disconnect();
    }

    // Update statistics
    stats_.active_connections.store(0);

    log_connection_event("Disconnected all connections");
}

void BaseConnectionManager::cleanup_disconnected_connections()
{
    std::lock_guard<std::mutex> lock(connections_mutex_);

    // Remove connections that are marked as disconnecting
    for (auto id : disconnecting_connections_)
    {
        active_connections_.erase(id);
    }
    disconnecting_connections_.clear();

    // Also remove any connections that are in DISCONNECTED state
    for (auto it = active_connections_.begin(); it != active_connections_.end();)
    {
        if (!it->second->is_connected() || it->second->get_state() == BaseClientConnection::State::DISCONNECTED)
        {
            it = active_connections_.erase(it);
            stats_.active_connections.fetch_sub(1);
        }
        else
        {
            ++it;
        }
    }
}

// =============================================================================
// Statistics
// =============================================================================

void BaseConnectionManager::reset_stats()
{
    stats_.total_connections.store(0);
    stats_.peak_connections.store(get_connection_count());
    stats_.total_packets_sent.store(0);
    stats_.total_packets_received.store(0);
    stats_.total_bytes_sent.store(0);
    stats_.total_bytes_received.store(0);

    log_connection_event("Statistics reset");
}

void BaseConnectionManager::print_stats() const
{
    std::cout << "\n=== Connection Manager Statistics ===" << std::endl;
    std::cout << "Active connections: " << stats_.active_connections.load() << std::endl;
    std::cout << "Total connections: " << stats_.total_connections.load() << std::endl;
    std::cout << "Peak connections: " << stats_.peak_connections.load() << std::endl;
    std::cout << "Packets sent: " << stats_.total_packets_sent.load() << std::endl;
    std::cout << "Packets received: " << stats_.total_packets_received.load() << std::endl;
    std::cout << "Bytes sent: " << format_bytes(stats_.total_bytes_sent.load()) << std::endl;
    std::cout << "Bytes received: " << format_bytes(stats_.total_bytes_received.load()) << std::endl;
    std::cout << "Max connections: " << config_.max_connections << std::endl;
    std::cout << "RSA key pool size: " << config_.rsa_key_pool_size << std::endl;
    std::cout << "=========================================\n"
              << std::endl;
}

// =============================================================================
// Configuration
// =============================================================================

void BaseConnectionManager::set_max_connections(uint32_t max_connections)
{
    config_.max_connections = max_connections;
    log_connection_event("Max connections set to " + std::to_string(max_connections));
}

// =============================================================================
// RSA Key Management
// =============================================================================

const ScrambledRSAKeyPair &BaseConnectionManager::get_random_rsa_key() const
{
    return rsa_manager_->getRandomRSAKeyPair();
}

// =============================================================================
// Packet Broadcasting
// =============================================================================

void BaseConnectionManager::broadcast_packet(std::unique_ptr<SendablePacket> packet)
{
    if (!packet)
    {
        return;
    }

    auto connections = get_all_connections();

    for (auto &connection : connections)
    {
        if (connection->is_connected())
        {
            // Create a copy of the packet for each connection
            auto packet_copy = std::unique_ptr<SendablePacket>(packet.get()); // This needs better cloning
            connection->send_packet(std::move(packet_copy));
        }
    }

    stats_.total_packets_sent.fetch_add(connections.size());
}

void BaseConnectionManager::broadcast_to_state(std::unique_ptr<SendablePacket> packet, BaseClientConnection::State state)
{
    if (!packet)
    {
        return;
    }

    auto connections = get_connections_by_state(state);

    for (auto &connection : connections)
    {
        if (connection->is_connected())
        {
            // Create a copy of the packet for each connection
            auto packet_copy = std::unique_ptr<SendablePacket>(packet.get()); // This needs better cloning
            connection->send_packet(std::move(packet_copy));
        }
    }

    stats_.total_packets_sent.fetch_add(connections.size());
}

// =============================================================================
// Internal Helpers
// =============================================================================

BaseConnectionManager::ConnectionId BaseConnectionManager::generate_connection_id()
{
    return next_connection_id_.fetch_add(1);
}

void BaseConnectionManager::handle_connection_disconnect(BaseClientConnection *connection)
{
    remove_connection(connection);
}

void BaseConnectionManager::update_peak_connections()
{
    uint32_t current = stats_.active_connections.load();
    uint32_t peak = stats_.peak_connections.load();

    while (current > peak && !stats_.peak_connections.compare_exchange_weak(peak, current))
    {
        // Loop until we successfully update or current <= peak
    }
}

void BaseConnectionManager::log_connection_event(const std::string &event) const
{
    if (config_.enable_connection_logging)
    {
        std::cout << "[BaseConnectionManager] " << event << std::endl;
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

std::string connection_state_to_string(BaseClientConnection::State state)
{
    switch (state)
    {
    case BaseClientConnection::State::CONNECTED:
        return "CONNECTED";
    case BaseClientConnection::State::DISCONNECTED:
        return "DISCONNECTED";
    default:
        return "UNKNOWN";
    }
}

std::string format_bytes(uint64_t bytes)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit < 4)
    {
        size /= 1024.0;
        unit++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

std::string format_duration(std::chrono::seconds duration)
{
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration % std::chrono::hours(1));
    auto seconds = duration % std::chrono::minutes(1);

    std::ostringstream oss;
    oss << hours.count() << "h " << minutes.count() << "m " << seconds.count() << "s";
    return oss.str();
}