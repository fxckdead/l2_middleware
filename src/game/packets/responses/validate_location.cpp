#include "validate_location.hpp"
#include <iostream>

// Constructor
ValidateLocation::ValidateLocation(const Player* player)
    : player_(player)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for ValidateLocation packet");
    }
}

void ValidateLocation::write(SendablePacketBuffer &buffer)
{
    // Write packet header
    buffer.writeUInt8(PACKET_ID); // 0x79 ValidateLocation

    std::cout << "[ValidateLocation] Sending position validation for: " << player_->getName() 
              << " at (" << player_->getX() << ", " << player_->getY() << ", " << player_->getZ() << ")" << std::endl;

    // Following L2J Mobius ValidateLocation.java structure EXACTLY
    
    // 1. Object ID
    buffer.writeUInt32(player_->getObjectId());
    
    // 2. X coordinate
    buffer.writeUInt32(player_->getX());
    
    // 3. Y coordinate
    buffer.writeUInt32(player_->getY());
    
    // 4. Z coordinate
    buffer.writeUInt32(player_->getZ());
    
    // 5. Heading (facing direction)
    buffer.writeUInt32(0); // TODO: Implement heading system

    std::cout << "[ValidateLocation] Position validation sent successfully" << std::endl;
}

size_t ValidateLocation::getSize() const
{
    // Calculate packet size based on L2J Mobius structure
    size_t size = 1; // opcode

    // Fixed-size fields (exactly like L2J Mobius)
    size += 4; // Object ID
    size += 4; // X coordinate
    size += 4; // Y coordinate
    size += 4; // Z coordinate
    size += 4; // Heading

    return size;
} 