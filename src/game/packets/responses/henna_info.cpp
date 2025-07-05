#include "henna_info.hpp"
#include <iostream>

// Constructor
HennaInfo::HennaInfo(const Player* player)
    : player_(player)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for HennaInfo packet");
    }
    buildHennaList();
}

void HennaInfo::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class

    std::cout << "[HennaInfo] Sending henna info for: " << player_->getName() << std::endl;

    // Following L2J Mobius HennaInfo.java structure EXACTLY
    
    // 1. Henna stat bonuses (6 bytes - INT, STR, CON, MEN, DEX, WIT)
    buffer.writeUInt8(0); // INT bonus (TODO: player_.getHennaStatINT())
    buffer.writeUInt8(0); // STR bonus (TODO: player_.getHennaStatSTR())
    buffer.writeUInt8(0); // CON bonus (TODO: player_.getHennaStatCON())
    buffer.writeUInt8(0); // MEN bonus (TODO: player_.getHennaStatMEN())
    buffer.writeUInt8(0); // DEX bonus (TODO: player_.getHennaStatDEX())
    buffer.writeUInt8(0); // WIT bonus (TODO: player_.getHennaStatWIT())
    
    // 2. Slots count (int)
    buffer.writeUInt32(3); // TODO: player_.getHennaSlots()
    
    // 3. Henna count (int)
    buffer.writeUInt32(static_cast<uint32_t>(hennas_.size()));
    
    // 4. Henna data
    for (const auto& henna : hennas_)
    {
        buffer.writeUInt32(henna.dyeId);
        buffer.writeUInt32(henna.count);
    }

    std::cout << "[HennaInfo] Henna info sent successfully (" << hennas_.size() << " hennas)" << std::endl;
}

size_t HennaInfo::getSize() const
{
    // Calculate packet size based on L2J Mobius structure
    size_t size = 1; // opcode

    // Fixed-size fields
    size += 6; // Henna stat bonuses (6 bytes)
    size += 4; // Slots count (int)
    size += 4; // Henna count (int)
    
    // Henna data
    size += hennas_.size() * 8; // Each henna: dyeId(4) + count(4)

    return size;
}

void HennaInfo::buildHennaList()
{
    // For now, return empty henna list since we don't have a henna system implemented
    // TODO: Implement actual henna loading from database/player data
    hennas_.clear();
    
    // Example hennas (commented out for now):
    /*
    // Basic henna dye
    hennas_.push_back({
        4445,  // dyeId (Basic Henna)
        1      // count
    });
    
    // Advanced henna dye
    hennas_.push_back({
        4446,  // dyeId (Advanced Henna)
        1      // count
    });
    */
} 