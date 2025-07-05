#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <string>

class AskJoinPledge : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x32;
    
    // Pledge invitation data
    uint32_t requestor_obj_id_;
    std::string sub_pledge_name_;
    uint32_t pledge_type_;
    std::string pledge_name_;

public:
    AskJoinPledge(uint32_t requestorObjId, const std::string& subPledgeName, 
                  uint32_t pledgeType, const std::string& pledgeName);

    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void write(SendablePacketBuffer &buffer) override;
}; 