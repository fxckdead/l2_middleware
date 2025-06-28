#pragma once

#include "../data/server_data.hpp"
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include <cstdint>

// GameServerManager - Manages registered game servers
// Provides similar functionality to the Rust gs_management.rs
// Handles server registration, listing, and basic management operations
class GameServerManager
{
private:
    std::unordered_map<uint8_t, ServerData> m_gameServers; // Registered game servers
    mutable std::mutex m_serversMutex;                     // Thread safety for server operations

public:
    GameServerManager() = default;
    ~GameServerManager() = default;

    // Disable copy operations for thread safety
    GameServerManager(const GameServerManager&) = delete;
    GameServerManager& operator=(const GameServerManager&) = delete;

    // Server registration and management
    bool registerGameServer(const ServerData& serverData);
    bool unregisterGameServer(uint8_t serverId);
    bool isServerRegistered(uint8_t serverId) const;

    // Server list operations
    std::vector<ServerData> getServerList() const;
    std::vector<ServerData> getServerListForClient(const std::string& clientIp) const;

    // Server information retrieval
    std::optional<ServerData> getServerById(uint8_t serverId) const;
    size_t getServerCount() const;

    // Server status operations
    bool updateServerStatus(uint8_t serverId, ServerStatus status);
    bool updateServerPlayerCount(uint8_t serverId, int32_t currentPlayers);

    // Validation and utility methods
    bool isValidServerId(uint8_t serverId) const;
    void clearAllServers();

    // For testing and debugging
    std::vector<uint8_t> getRegisteredServerIds() const;

private:
    // Helper methods
    bool isServerDataValid(const ServerData& serverData) const;
    uint8_t findNextAvailableServerId() const;
}; 