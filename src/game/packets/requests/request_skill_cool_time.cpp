#include "request_skill_cool_time.hpp"

uint8_t RequestSkillCoolTime::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> RequestSkillCoolTime::getExPacketId() const
{
    return std::nullopt;
}

void RequestSkillCoolTime::read(ReadablePacketBuffer &buffer)
{
    // RequestSkillCoolTime is typically a simple request packet
    // that doesn't contain additional data - client just wants to know
    // current skill cooldown status
    // If there are any fields, they would be read here
}

bool RequestSkillCoolTime::isValid() const
{
    return true;
} 