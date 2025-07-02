#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

class RequestGameStart : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x0D;
    
    // Character selection data
    int32_t character_object_id_ = 0;

public:
    RequestGameStart() = default;

    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    bool isValid() const;
    
    // Getter for character selection
    int32_t getCharacterObjectId() const { return character_object_id_; }
};