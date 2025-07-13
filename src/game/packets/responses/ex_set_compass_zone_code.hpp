#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

// ExSetCompassZoneCode - Server response setting compass zone information
// Tells the client what type of zone the player is in (PvP, Peace, Siege, etc.)
// Based on L2J Mobius ExSetCompassZoneCode.java implementation
class ExSetCompassZoneCode : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xFE; // Extended packet identifier
    static constexpr uint16_t EX_PACKET_ID = 0x32; // ExSetCompassZoneCode - Interlude Update 3
    
    uint32_t m_zoneType;

public:
    // Zone type constants from L2J Mobius
    static constexpr uint32_t ALTEREDZONE = 0x08;
    static constexpr uint32_t SIEGEWARZONE1 = 0x0A;
    static constexpr uint32_t SIEGEWARZONE2 = 0x0B;
    static constexpr uint32_t PEACEZONE = 0x0C;
    static constexpr uint32_t SEVENSIGNSZONE = 0x0D;
    static constexpr uint32_t PVPZONE = 0x0E;
    static constexpr uint32_t GENERALZONE = 0x0F;

    // Constructor - create with zone type
    explicit ExSetCompassZoneCode(uint32_t zoneType = GENERALZONE);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return EX_PACKET_ID; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
}; 