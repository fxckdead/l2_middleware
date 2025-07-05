#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <string>

class NpcHtmlMessage : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x0F;
    
    // HTML message data
    uint32_t npc_obj_id_;
    std::string html_content_;
    uint32_t item_id_;

public:
    // Constructors matching L2J Mobius
    NpcHtmlMessage();
    explicit NpcHtmlMessage(uint32_t npcObjId);
    explicit NpcHtmlMessage(const std::string& html);
    NpcHtmlMessage(uint32_t npcObjId, const std::string& html);
    NpcHtmlMessage(uint32_t npcObjId, uint32_t itemId);
    NpcHtmlMessage(uint32_t npcObjId, uint32_t itemId, const std::string& html);

    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 