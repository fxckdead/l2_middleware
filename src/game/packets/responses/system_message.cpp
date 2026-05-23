#include "system_message.hpp"
#include <iostream>

// Constructor with message ID
SystemMessage::SystemMessage(int32_t messageId)
    : messageId_(messageId)
{
}

// Constructor with text message
SystemMessage::SystemMessage(const std::string& text)
    : messageId_(1) // Default message ID for text messages
{
    addString(text);
}

void SystemMessage::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class

    std::cout << "[SystemMessage] Sending system message ID: " << messageId_ << std::endl;

    // Following L2J Mobius SystemMessage.java structure EXACTLY
    
    // 1. Message ID (int)
    buffer.writeUInt32(static_cast<uint32_t>(messageId_));
    
    // 2. Parameter count (int)
    buffer.writeUInt32(static_cast<uint32_t>(parameters_.size()));
    
    // 3. Parameters
    for (const auto& param : parameters_)
    {
        // Parameter type (int)
        buffer.writeUInt32(static_cast<uint32_t>(param.type));
        
        // Parameter value based on type
        switch (param.type)
        {
            case ParamType::TYPE_TEXT:
            case ParamType::TYPE_PLAYER_NAME:
            {
                buffer.writeCUtf16leString(param.stringValue);
                break;
            }
            case ParamType::TYPE_LONG_NUMBER:
            {
                buffer.writeUInt64(static_cast<uint64_t>(param.longValue));
                break;
            }
            case ParamType::TYPE_SKILL_NAME:
            {
                if (param.intArrayValue.size() >= 2)
                {
                    buffer.writeUInt32(static_cast<uint32_t>(param.intArrayValue[0])); // SkillId
                    buffer.writeUInt32(static_cast<uint32_t>(param.intArrayValue[1])); // SkillLevel
                }
                break;
            }
            case ParamType::TYPE_ZONE_NAME:
            {
                if (param.intArrayValue.size() >= 3)
                {
                    buffer.writeUInt32(static_cast<uint32_t>(param.intArrayValue[0])); // x
                    buffer.writeUInt32(static_cast<uint32_t>(param.intArrayValue[1])); // y
                    buffer.writeUInt32(static_cast<uint32_t>(param.intArrayValue[2])); // z
                }
                break;
            }
            default: // All other types use int value
            {
                buffer.writeUInt32(static_cast<uint32_t>(param.intValue));
                break;
            }
        }
    }

    std::cout << "[SystemMessage] System message sent successfully (" << parameters_.size() << " parameters)" << std::endl;
}

size_t SystemMessage::getSize() const
{
    // Calculate packet size based on L2J Mobius structure
    size_t size = 1; // opcode

    // Fixed-size fields
    size += 4; // Message ID (int)
    size += 4; // Parameter count (int)
    
    // Parameters
    for (const auto& param : parameters_)
    {
        size += 4; // Parameter type (int)
        
        switch (param.type)
        {
            case ParamType::TYPE_TEXT:
            case ParamType::TYPE_PLAYER_NAME:
            {
                size += (param.stringValue.length() + 1) * 2; // UTF-16LE + null
                break;
            }
            case ParamType::TYPE_LONG_NUMBER:
            {
                size += 8; // long value
                break;
            }
            case ParamType::TYPE_SKILL_NAME:
            {
                size += 8; // 2 int values
                break;
            }
            case ParamType::TYPE_ZONE_NAME:
            {
                size += 12; // 3 int values
                break;
            }
            default: // All other types use int value
            {
                size += 4; // int value
                break;
            }
        }
    }

    return size;
}

// Parameter helper methods
void SystemMessage::addParameter(ParamType type, const std::string& value)
{
    ParamData param;
    param.type = type;
    param.stringValue = value;
    parameters_.push_back(param);
}

void SystemMessage::addParameter(ParamType type, int32_t value)
{
    ParamData param;
    param.type = type;
    param.intValue = value;
    parameters_.push_back(param);
}

void SystemMessage::addParameter(ParamType type, int64_t value)
{
    ParamData param;
    param.type = type;
    param.longValue = value;
    parameters_.push_back(param);
}

void SystemMessage::addParameter(ParamType type, const std::vector<int32_t>& values)
{
    ParamData param;
    param.type = type;
    param.intArrayValue = values;
    parameters_.push_back(param);
}

// Public parameter methods
SystemMessage& SystemMessage::addString(const std::string& text)
{
    addParameter(ParamType::TYPE_TEXT, text);
    return *this;
}

SystemMessage& SystemMessage::addInt(int32_t number)
{
    addParameter(ParamType::TYPE_INT_NUMBER, number);
    return *this;
}

SystemMessage& SystemMessage::addLong(int64_t number)
{
    addParameter(ParamType::TYPE_LONG_NUMBER, number);
    return *this;
}

SystemMessage& SystemMessage::addPlayerName(const std::string& playerName)
{
    addParameter(ParamType::TYPE_PLAYER_NAME, playerName);
    return *this;
}

SystemMessage& SystemMessage::addNpcName(int32_t npcId)
{
    addParameter(ParamType::TYPE_NPC_NAME, 1000000 + npcId); // L2J Mobius format
    return *this;
}

SystemMessage& SystemMessage::addItemName(int32_t itemId)
{
    addParameter(ParamType::TYPE_ITEM_NAME, itemId);
    return *this;
}

SystemMessage& SystemMessage::addSkillName(int32_t skillId, int32_t skillLevel)
{
    std::vector<int32_t> values = {skillId, skillLevel};
    addParameter(ParamType::TYPE_SKILL_NAME, values);
    return *this;
}

SystemMessage& SystemMessage::addZoneName(int32_t x, int32_t y, int32_t z)
{
    std::vector<int32_t> values = {x, y, z};
    addParameter(ParamType::TYPE_ZONE_NAME, values);
    return *this;
} 