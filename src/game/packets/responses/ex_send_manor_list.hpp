#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <vector>

class ExSendManorList : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xFE;
    static constexpr uint16_t EX_PACKET_ID = 0x1B;
    
    // Castle data structure (matches L2J Mobius Castle.getResidenceId() and Castle.getName())
    struct CastleData {
        uint32_t residence_id;  // castle.getResidenceId()
        std::string castle_name; // castle.getName().toLowerCase()
    };
    
    std::vector<CastleData> castles_;

public:
    explicit ExSendManorList();

    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 