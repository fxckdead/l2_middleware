#include "request_manor_list.hpp"

uint8_t RequestManorList::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> RequestManorList::getExPacketId() const
{
    return EX_PACKET_ID;
}

void RequestManorList::read(ReadablePacketBuffer &buffer)
{
    // RequestManorList has empty readImpl() in L2J Mobius - no data to read
    // The packet is just a request for manor information
}

bool RequestManorList::isValid() const
{
    return true;
} 