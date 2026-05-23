#include "show_mini_map.hpp"
#include <iostream>

ShowMiniMap::ShowMiniMap(int mapId) : map_id_(mapId)
{
}

void ShowMiniMap::write(SendablePacketBuffer& buffer)
{
    std::cout << "[ShowMiniMap] Sending minimap display packet with map ID: " << map_id_ << std::endl;
    
    // Opcode is written automatically by base class
    buffer.writeInt32(map_id_); // Map ID (default 1665 from L2J Mobius)
}

size_t ShowMiniMap::getSize() const
{
    // Packet ID (1 byte) + Map ID (4 bytes)
    return 5;
} 