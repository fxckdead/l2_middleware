#include "game_server_manager.hpp"
#include <algorithm>
#include <stdexcept>

// Server registration and management
bool GameServerManager::registerGameServer(const ServerData& serverData)
{
    std::lock_guard<std::mutex> lock(m_serversMutex);
    
    if (!isServerDataValid(serverData))
    {
        return false;
    }
    
    uint8_t serverId = static_cast<uint8_t>(serverData.serverId);
    
    // Check if server ID is already registered
    if (m_gameServers.find(serverId) != m_gameServers.end())
    {
        return false; // Server already registered
    }
    
    // Register the server
    m_gameServers[serverId] = serverData;
    return true;
}

bool GameServerManager::unregisterGameServer(uint8_t serverId)
{
    std::lock_guard<std::mutex> lock(m_serversMutex);
    
    auto it = m_gameServers.find(serverId);
    if (it != m_gameServers.end())
    {
        m_gameServers.erase(it);
        return true;
    }
    
    return false; // Server not found
}

bool GameServerManager::isServerRegistered(uint8_t serverId) const
{
    std::lock_guard<std::mutex> lock(m_serversMutex);
    return m_gameServers.find(serverId) != m_gameServers.end();
}

// Server list operations
std::vector<ServerData> GameServerManager::getServerList() const
{
    std::lock_guard<std::mutex> lock(m_serversMutex);
    
    std::vector<ServerData> servers;
    servers.reserve(m_gameServers.size());
    
    for (const auto& [serverId, serverData] : m_gameServers)
    {
        servers.push_back(serverData);
    }
    
    // Sort by server ID for consistent ordering
    std::sort(servers.begin(), servers.end(), 
              [](const ServerData& a, const ServerData& b) {
                  return a.serverId < b.serverId;
              });
    
    return servers;
}

std::vector<ServerData> GameServerManager::getServerListForClient(const std::string& clientIp) const
{
    // For now, return all servers regardless of client IP
    // This can be extended later to implement IP-based filtering like in Rust implementation
    return getServerList();
}

// Server information retrieval
std::optional<ServerData> GameServerManager::getServerById(uint8_t serverId) const
{
    std::lock_guard<std::mutex> lock(m_serversMutex);
    
    auto it = m_gameServers.find(serverId);
    if (it != m_gameServers.end())
    {
        return it->second;
    }
    
    return std::nullopt;
}

size_t GameServerManager::getServerCount() const
{
    std::lock_guard<std::mutex> lock(m_serversMutex);
    return m_gameServers.size();
}

// Server status operations
bool GameServerManager::updateServerStatus(uint8_t serverId, ServerStatus status)
{
    std::lock_guard<std::mutex> lock(m_serversMutex);
    
    auto it = m_gameServers.find(serverId);
    if (it != m_gameServers.end())
    {
        it->second.status = status;
        return true;
    }
    
    return false;
}

bool GameServerManager::updateServerPlayerCount(uint8_t serverId, int32_t currentPlayers)
{
    std::lock_guard<std::mutex> lock(m_serversMutex);
    
    auto it = m_gameServers.find(serverId);
    if (it != m_gameServers.end())
    {
        if (currentPlayers >= 0 && currentPlayers <= it->second.maxPlayers)
        {
            it->second.currentPlayers = currentPlayers;
            return true;
        }
    }
    
    return false;
}

// Validation and utility methods
bool GameServerManager::isValidServerId(uint8_t serverId) const
{
    // Server ID 0 is typically reserved, so start from 1
    return serverId > 0;
}

void GameServerManager::clearAllServers()
{
    std::lock_guard<std::mutex> lock(m_serversMutex);
    m_gameServers.clear();
}

// For testing and debugging
std::vector<uint8_t> GameServerManager::getRegisteredServerIds() const
{
    std::lock_guard<std::mutex> lock(m_serversMutex);
    
    std::vector<uint8_t> serverIds;
    serverIds.reserve(m_gameServers.size());
    
    for (const auto& [serverId, serverData] : m_gameServers)
    {
        serverIds.push_back(serverId);
    }
    
    std::sort(serverIds.begin(), serverIds.end());
    return serverIds;
}

// Helper methods
bool GameServerManager::isServerDataValid(const ServerData& serverData) const
{
    // Use the ServerData's built-in validation
    if (!serverData.isValid())
    {
        return false;
    }
    
    // Additional validation for server ID
    if (!isValidServerId(static_cast<uint8_t>(serverData.serverId)))
    {
        return false;
    }
    
    return true;
}

uint8_t GameServerManager::findNextAvailableServerId() const
{
    // Find the next available server ID starting from 1
    for (uint8_t id = 1; id != 0; ++id) // Will wrap around at 255
    {
        if (m_gameServers.find(id) == m_gameServers.end())
        {
            return id;
        }
    }
    
    return 0; // No available ID found
} 