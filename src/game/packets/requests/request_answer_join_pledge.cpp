#include "request_answer_join_pledge.hpp"

uint8_t RequestAnswerJoinPledge::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> RequestAnswerJoinPledge::getExPacketId() const
{
    return std::nullopt;
}

void RequestAnswerJoinPledge::read(ReadablePacketBuffer &buffer)
{
    // Read pledge join response data (matches L2J Mobius: _answer = readInt())
    response_ = buffer.readUInt32();
}

bool RequestAnswerJoinPledge::isValid() const
{
    // Response should be 0 (decline) or 1 (accept)
    return response_ <= 1;
}