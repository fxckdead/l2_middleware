#include "status_update.hpp"
#include <iostream>

StatusUpdate::StatusUpdate(const Player* player)
    : player_(player)
{
}

void StatusUpdate::write(SendablePacketBuffer &buffer)
{
    // StatusUpdate packet format (based on L2J Mobius):
    // - uint32: object_id
    // - uint32: attribute_count (how many attributes we're updating)
    // For each attribute:
    //   - uint32: attribute_id (09=HP, 0A=MP, 0B=CP)
    //   - uint32: attribute_value
    
    buffer.writeUInt32(player_->getObjectId());
    
    // Send 3 attributes: HP, MP, CP
    buffer.writeUInt32(3);
    
    // HP (attribute ID 0x09)
    buffer.writeUInt32(0x09);
    buffer.writeUInt32(static_cast<uint32_t>(player_->getCurrentHp()));
    
    // MP (attribute ID 0x0A) 
    buffer.writeUInt32(0x0A);
    buffer.writeUInt32(static_cast<uint32_t>(player_->getCurrentMp()));
    
    // CP (attribute ID 0x0B)
    buffer.writeUInt32(0x0B);
    buffer.writeUInt32(static_cast<uint32_t>(player_->getCurrentCp()));
    
    std::cout << "[StatusUpdate] Sending HP/MP/CP status for: " << player_->getName() 
              << " (HP:" << player_->getCurrentHp() << ", MP:" << player_->getCurrentMp() 
              << ", CP:" << player_->getCurrentCp() << ")" << std::endl;
}

size_t StatusUpdate::getSize() const
{
    // object_id(4) + attribute_count(4) + 3 * (attribute_id(4) + value(4)) = 32 bytes
    return 32;
} 