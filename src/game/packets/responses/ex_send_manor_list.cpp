#include "ex_send_manor_list.hpp"
#include <iostream>

ExSendManorList::ExSendManorList()
{
    // Based on L2J Mobius: send castle list sorted by residence ID
    // Castle names are sent in lowercase as per L2J Mobius implementation
    castles_.clear();
    
    // Standard Interlude castles (sorted by residence ID)
    castles_.push_back({1, "gludio"});
    castles_.push_back({2, "dion"});
    castles_.push_back({3, "giran"});
    castles_.push_back({4, "oren"});
    castles_.push_back({5, "aden"});
    castles_.push_back({6, "innadril"});
    castles_.push_back({7, "goddard"});
    castles_.push_back({8, "rune"});
    castles_.push_back({9, "schuttgart"});
}

uint8_t ExSendManorList::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> ExSendManorList::getExPacketId() const
{
    return EX_PACKET_ID;
}

void ExSendManorList::write(SendablePacketBuffer &buffer)
{
    // Write castle count (matches L2J Mobius: buffer.writeInt(castles.size()))
    buffer.writeUInt32(static_cast<uint32_t>(castles_.size()));
    
    // Write each castle (matches L2J Mobius structure exactly)
    for (const auto& castle : castles_)
    {
        buffer.writeUInt32(castle.residence_id);     // castle.getResidenceId()
        buffer.writeCUtf16leString(castle.castle_name); // castle.getName().toLowerCase()
    }
    
    std::cout << "[ExSendManorList] Sending castle list with " << castles_.size() << " castles" << std::endl;
}

size_t ExSendManorList::getSize() const
{
    // Calculate packet size: extended opcode + castle count + castle data
    size_t size = 3; // 0xFE + 16-bit sub-opcode
    size += 4; // castle count (uint32)
    
    for (const auto& castle : castles_)
    {
        size += 4; // residence_id (uint32)
        size += (castle.castle_name.length() + 1) * 2; // castle_name (UTF-16LE + null)
    }
    
    return size;
} 