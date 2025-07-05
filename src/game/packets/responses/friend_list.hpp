#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <vector>
#include <string>

// FriendList - Server response with friend list information
// Shows friends and their online status
class FriendList : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xFA; // FriendList - Interlude Update 3
    const Player* player_;
    
    // Friend data structure (matches L2J Mobius)
    struct FriendData {
        uint32_t objId;
        std::string name;
        bool online;
        uint32_t onlineObjId;
    };
    
    std::vector<FriendData> friends_;
    
    void buildFriendList();

public:
    // Constructor - create with player data
    explicit FriendList(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 