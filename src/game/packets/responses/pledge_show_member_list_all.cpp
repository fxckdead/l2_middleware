#include "pledge_show_member_list_all.hpp"
#include <iostream>

// Constructor
PledgeShowMemberListAll::PledgeShowMemberListAll(const Player* player)
    : player_(player)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for PledgeShowMemberListAll packet");
    }
}

void PledgeShowMemberListAll::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class

    std::cout << "[PledgeShowMemberListAll] Sending clan member list for: " << player_->getName() << std::endl;

    // TODO: Implement actual clan member list
    // For now, send empty list since we don't have a clan system implemented
    
    // Clan member count (int)
    buffer.writeUInt32(0);

    std::cout << "[PledgeShowMemberListAll] Clan member list sent successfully (0 members)" << std::endl;
}

size_t PledgeShowMemberListAll::getSize() const
{
    // Calculate packet size
    size_t size = 1; // opcode
    size += 4; // Member count (int)
    
    // TODO: Add size calculation for actual clan members when implemented

    return size;
} 