#include "pledge_status_changed.hpp"
#include <iostream>

// Constructor
PledgeStatusChanged::PledgeStatusChanged(const Player* player)
    : player_(player)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for PledgeStatusChanged packet");
    }
}

void PledgeStatusChanged::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class

    std::cout << "[PledgeStatusChanged] Sending clan status update for: " << player_->getName() << std::endl;

    // TODO: Implement actual clan status update
    // For now, send minimal data since we don't have a clan system implemented
    
    // Clan ID
    buffer.writeUInt32(player_->getClanId());
    
    // Clan status (0 = no clan)
    buffer.writeUInt32(0);

    std::cout << "[PledgeStatusChanged] Clan status update sent successfully" << std::endl;
}

size_t PledgeStatusChanged::getSize() const
{
    // Calculate packet size
    size_t size = 1; // opcode
    size += 4; // Clan ID (int)
    size += 4; // Clan status (int)

    return size;
} 