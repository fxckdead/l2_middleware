#include "ask_join_pledge.hpp"

AskJoinPledge::AskJoinPledge(uint32_t requestorObjId, const std::string& subPledgeName, 
                             uint32_t pledgeType, const std::string& pledgeName)
    : requestor_obj_id_(requestorObjId)
    , sub_pledge_name_(subPledgeName)
    , pledge_type_(pledgeType)
    , pledge_name_(pledgeName)
{
}

uint8_t AskJoinPledge::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> AskJoinPledge::getExPacketId() const
{
    return std::nullopt;
}

void AskJoinPledge::write(SendablePacketBuffer &buffer)
{
    // Write requestor object ID
    buffer.writeUInt32(requestor_obj_id_);
    
    // Write sub-pledge name or main pledge name based on pledge type
    if (!sub_pledge_name_.empty())
    {
        if (pledge_type_ > 0)
        {
            buffer.writeCUtf16leString(sub_pledge_name_);
        }
        else
        {
            buffer.writeCUtf16leString(pledge_name_);
        }
    }
    
    // Write pledge type if not 0
    if (pledge_type_ != 0)
    {
        buffer.writeUInt32(pledge_type_);
    }
    
    // Write main pledge name
    buffer.writeCUtf16leString(pledge_name_);
} 