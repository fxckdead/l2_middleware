#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <vector>
#include <cstdint>

// CharacterCreateSuccess
// Echoes back the ping data to confirm connectivity
class CharacterCreateSuccess : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x19; // CharacterCreateSuccess - Interlude Update 3

public:
    // Constructor
    explicit CharacterCreateSuccess();

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;

    // Debug string representation
    std::string toString() const;
};