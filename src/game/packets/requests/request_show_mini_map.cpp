#include "request_show_mini_map.hpp"
#include <iostream>

uint8_t RequestShowMiniMap::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> RequestShowMiniMap::getExPacketId() const
{
    return std::nullopt;
}

void RequestShowMiniMap::read(ReadablePacketBuffer &buffer)
{
    // RequestShowMiniMap has no additional data to read (like L2J Mobius - empty readImpl())
    // Client is simply requesting to show/toggle the minimap
    std::cout << "[RequestShowMiniMap] Client requesting minimap display" << std::endl;
}

bool RequestShowMiniMap::isValid() const
{
    // Simple request packet - always valid
    return true;
} 