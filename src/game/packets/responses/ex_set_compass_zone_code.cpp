#include "ex_set_compass_zone_code.hpp"
#include <iostream>

// Constructor
ExSetCompassZoneCode::ExSetCompassZoneCode(uint32_t zoneType) : m_zoneType(zoneType)
{
}

void ExSetCompassZoneCode::write(SendablePacketBuffer& buffer)
{
    // Opcode and extended opcode are written automatically by base class
    
    const char* zoneTypeName = "UNKNOWN";
    switch (m_zoneType)
    {
        case ALTEREDZONE: zoneTypeName = "ALTEREDZONE"; break;
        case SIEGEWARZONE1: zoneTypeName = "SIEGEWARZONE1"; break;
        case SIEGEWARZONE2: zoneTypeName = "SIEGEWARZONE2"; break;
        case PEACEZONE: zoneTypeName = "PEACEZONE"; break;
        case SEVENSIGNSZONE: zoneTypeName = "SEVENSIGNSZONE"; break;
        case PVPZONE: zoneTypeName = "PVPZONE"; break;
        case GENERALZONE: zoneTypeName = "GENERALZONE"; break;
    }
    
    std::cout << "[ExSetCompassZoneCode] Setting compass zone to: " << zoneTypeName 
              << " (0x" << std::hex << m_zoneType << std::dec << ")" << std::endl;
    
    // Following L2J Mobius ExSetCompassZoneCode.java structure EXACTLY
    
    // 1. Zone type
    buffer.writeUInt32(m_zoneType);
}

size_t ExSetCompassZoneCode::getSize() const
{
    // Extended packet: Packet ID (1) + Extended ID (2) + zoneType (4) = 7 bytes
    return 7;
} 