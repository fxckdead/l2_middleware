#include "server_list_response.hpp"

// Constructors
ServerListResponse::ServerListResponse(const std::vector<ServerData>& servers)
    : m_servers(servers), m_lastServer(255), m_charsOnServer(std::nullopt)
{
}

ServerListResponse::ServerListResponse(const std::vector<ServerData>& servers, uint8_t lastServer)
    : m_servers(servers), m_lastServer(lastServer), m_charsOnServer(std::nullopt)
{
}

ServerListResponse::ServerListResponse(const std::vector<ServerData>& servers, uint8_t lastServer,
                                     const std::unordered_map<uint8_t, GSCharsInfo>& charsOnServer)
    : m_servers(servers), m_lastServer(lastServer), m_charsOnServer(charsOnServer)
{
}

// SendablePacket interface implementation
uint8_t ServerListResponse::getPacketId() const
{
    return OPCODE;
}

std::optional<uint16_t> ServerListResponse::getExPacketId() const
{
    return std::nullopt; // ServerList response doesn't have extended packet ID
}

void ServerListResponse::write(SendablePacketBuffer &buffer)
{
    // Write packet structure exactly matching Rust implementation:
    // opcode + server_count + last_server + server_data_for_each + trailer + character_info

    // Header
    buffer.writeUInt8(OPCODE);                              // Opcode: 0x04 (ServerList)
    buffer.writeUInt8(static_cast<uint8_t>(m_servers.size())); // Server count
    buffer.writeUInt8(m_lastServer);                        // Last server selection

    // Write each server's data
    for (const auto& server : m_servers)
    {
        writeServerData(buffer, server);
    }

    // Write trailer (unknown value 0xA4)
    buffer.writeInt16(0xA4);

    // Write character information if available
    writeCharacterInfo(buffer);
}

size_t ServerListResponse::getSize() const
{
    return calculatePacketSize();
}

// Mutators
void ServerListResponse::setServers(const std::vector<ServerData>& servers)
{
    m_servers = servers;
}

void ServerListResponse::setLastServer(uint8_t lastServer)
{
    m_lastServer = lastServer;
}

void ServerListResponse::setCharsOnServer(const std::unordered_map<uint8_t, GSCharsInfo>& charsOnServer)
{
    m_charsOnServer = charsOnServer;
}

// Factory methods
ServerListResponse ServerListResponse::create(const std::vector<ServerData>& servers)
{
    return ServerListResponse(servers, 255);
}

ServerListResponse ServerListResponse::createWithCharacterInfo(const std::vector<ServerData>& servers,
                                                              const std::unordered_map<uint8_t, GSCharsInfo>& charsOnServer)
{
    return ServerListResponse(servers, 255, charsOnServer);
}

// Validation
bool ServerListResponse::isValid() const
{
    // Validate that all servers are valid
    for (const auto& server : m_servers)
    {
        if (!server.isValid())
        {
            return false;
        }
    }
    
    // Check server count limit (should fit in uint8_t)
    if (m_servers.size() > 255)
    {
        return false;
    }
    
    return true;
}

// Helper methods for writing server data
void ServerListResponse::writeServerData(SendablePacketBuffer &buffer, const ServerData& server)
{
    // Write server data exactly matching Rust implementation structure
    
    // Server ID
    buffer.writeUInt8(static_cast<uint8_t>(server.serverId));
    
    // IP address as 4 octets
    auto ipOctets = server.getIpOctets();
    buffer.writeUInt8(ipOctets[0]);
    buffer.writeUInt8(ipOctets[1]);
    buffer.writeUInt8(ipOctets[2]);
    buffer.writeUInt8(ipOctets[3]);
    
    // Port
    buffer.writeInt32(server.port);
    
    // Age limit
    buffer.writeUInt8(static_cast<uint8_t>(server.ageLimit));
    
    // PvP flag
    buffer.writeUInt8(server.pvp ? 0x01 : 0x00);
    
    // Player counts
    buffer.writeInt16(static_cast<int16_t>(server.currentPlayers));
    buffer.writeInt16(static_cast<int16_t>(server.maxPlayers));
    
    // Server status (true if not Down)
    bool serverOnline = server.status.has_value() && server.status.value() != ServerStatus::Down;
    buffer.writeUInt8(serverOnline ? 0x01 : 0x00);
    
    // Server type (using 1024 as default for Normal, matching Rust implementation)
    int32_t serverTypeValue = 1024; // Default for Normal
    if (server.serverType.has_value())
    {
        serverTypeValue = static_cast<int32_t>(server.serverType.value());
    }
    buffer.writeInt32(serverTypeValue);
    
    // Brackets flag
    buffer.writeUInt8(server.brackets ? 0x01 : 0x00);
}

void ServerListResponse::writeCharacterInfo(SendablePacketBuffer &buffer)
{
    // Write character information if available (matches Rust implementation)
    if (m_charsOnServer.has_value())
    {
        for (const auto& [serverId, charsInfo] : m_charsOnServer.value())
        {
            buffer.writeUInt8(serverId);
            buffer.writeUInt8(charsInfo.totalChars);
        }
    }
}

size_t ServerListResponse::calculatePacketSize() const
{
    // Calculate total packet size:
    // Header: 1 (opcode) + 1 (server_count) + 1 (last_server) = 3 bytes
    // Per server: 1 (id) + 4 (ip) + 4 (port) + 1 (age) + 1 (pvp) + 2 (current) + 2 (max) + 1 (status) + 4 (type) + 1 (brackets) = 21 bytes
    // Trailer: 2 (unknown 0xA4) = 2 bytes
    // Character info: 2 bytes per server with characters
    
    size_t size = 3; // Header
    size += m_servers.size() * 21; // Server data
    size += 2; // Trailer
    
    if (m_charsOnServer.has_value())
    {
        size += m_charsOnServer.value().size() * 2; // Character info
    }
    
    return size;
} 