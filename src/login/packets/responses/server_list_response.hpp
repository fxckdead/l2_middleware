#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../data/server_data.hpp"
#include <vector>
#include <unordered_map>
#include <cstdint>

// ServerListResponse - Response packet containing available game servers (opcode 0x04)
// Matches ServerList from Rust implementation
// This packet is sent in response to RequestServerList to provide available game servers
class ServerListResponse : public SendablePacket
{
private:
    static constexpr uint8_t OPCODE = 0x04; // LoginServerOpcodes::ServerList

    std::vector<ServerData> m_servers;                                    // List of available servers
    uint8_t m_lastServer;                                                 // Last selected server (currently unused)
    std::optional<std::unordered_map<uint8_t, GSCharsInfo>> m_charsOnServer; // Character counts per server

public:
    // Constructors
    ServerListResponse() = default;
    explicit ServerListResponse(const std::vector<ServerData>& servers);
    ServerListResponse(const std::vector<ServerData>& servers, uint8_t lastServer);
    ServerListResponse(const std::vector<ServerData>& servers, uint8_t lastServer,
                      const std::unordered_map<uint8_t, GSCharsInfo>& charsOnServer);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;

    // Accessors
    const std::vector<ServerData>& getServers() const { return m_servers; }
    uint8_t getLastServer() const { return m_lastServer; }
    const std::optional<std::unordered_map<uint8_t, GSCharsInfo>>& getCharsOnServer() const { return m_charsOnServer; }

    // Mutators
    void setServers(const std::vector<ServerData>& servers);
    void setLastServer(uint8_t lastServer);
    void setCharsOnServer(const std::unordered_map<uint8_t, GSCharsInfo>& charsOnServer);

    // Factory methods
    static ServerListResponse create(const std::vector<ServerData>& servers);
    static ServerListResponse createWithCharacterInfo(const std::vector<ServerData>& servers,
                                                     const std::unordered_map<uint8_t, GSCharsInfo>& charsOnServer);

    // Validation
    bool isValid() const;

private:
    // Helper methods for writing server data
    void writeServerData(SendablePacketBuffer &buffer, const ServerData& server);
    void writeCharacterInfo(SendablePacketBuffer &buffer);
    
    // Calculate dynamic packet size
    size_t calculatePacketSize() const;
}; 