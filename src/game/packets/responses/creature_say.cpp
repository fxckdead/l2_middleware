#include "creature_say.hpp"
#include <iostream>

// Constructor with creature, chat type, sender name, and text
CreatureSay::CreatureSay(const Player* sender, ChatType chatType, const std::string& senderName, const std::string& text)
    : m_objectId(sender ? sender->getObjectId() : 0),
      m_chatType(chatType),
      m_senderName(senderName),
      m_text(text),
      m_charId(0),
      m_messageId(0)
{
}

// Constructor with creature, chat type, and text (uses creature's name)
CreatureSay::CreatureSay(const Player* sender, ChatType chatType, const std::string& text)
    : m_objectId(sender ? sender->getObjectId() : 0),
      m_chatType(chatType),
      m_senderName(sender ? sender->getName() : ""),
      m_text(text),
      m_charId(0),
      m_messageId(0)
{
}

// Constructor for system messages
CreatureSay::CreatureSay(ChatType chatType, uint32_t charId, uint32_t messageId)
    : m_objectId(0),
      m_chatType(chatType),
      m_senderName(""),
      m_text(""),
      m_charId(charId),
      m_messageId(messageId)
{
}

void CreatureSay::addStringParameter(const std::string& text)
{
    m_parameters.push_back(text);
}

void CreatureSay::write(SendablePacketBuffer& buffer)
{
    // Opcode is written automatically by base class
    
    std::cout << "[CreatureSay] " << getChatTypeName() << " from '" << m_senderName 
              << "' (ID: " << m_objectId << "): " << m_text << std::endl;
    
    // Following L2J Mobius CreatureSay.java structure EXACTLY
    
    // 1. Object ID (0 if no sender)
    buffer.writeUInt32(m_objectId);
    
    // 2. Chat type
    buffer.writeUInt32(getChatTypeClientId());
    
    // 3. Sender name or character ID
    if (!m_senderName.empty())
    {
        buffer.writeCUtf16leString(m_senderName);
    }
    else
    {
        buffer.writeUInt32(m_charId);
    }
    
    // 4. Message ID or text or parameters
    if (m_messageId != 0)
    {
        buffer.writeUInt32(m_messageId);
    }
    else if (!m_text.empty())
    {
        buffer.writeCUtf16leString(m_text);
    }
    else if (!m_parameters.empty())
    {
        for (const auto& param : m_parameters)
        {
            buffer.writeCUtf16leString(param);
        }
    }
}

size_t CreatureSay::getSize() const
{
    size_t size = 1 + 4 + 4; // Packet ID + object ID + chat type
    
    if (!m_senderName.empty())
    {
        size += 2 + (m_senderName.length() * 2); // UTF-16LE string
    }
    else
    {
        size += 4; // Character ID
    }
    
    if (m_messageId != 0)
    {
        size += 4; // Message ID
    }
    else if (!m_text.empty())
    {
        size += 2 + (m_text.length() * 2); // UTF-16LE string
    }
    else if (!m_parameters.empty())
    {
        for (const auto& param : m_parameters)
        {
            size += 2 + (param.length() * 2); // UTF-16LE string
        }
    }
    
    return size;
}

uint32_t CreatureSay::getChatTypeClientId() const
{
    // Return the enum value directly as it matches L2J Mobius ChatType.getClientId()
    return static_cast<uint32_t>(m_chatType);
}

const char* CreatureSay::getChatTypeName() const
{
    switch (m_chatType)
    {
        case ChatType::GENERAL: return "GENERAL";
        case ChatType::SHOUT: return "SHOUT";
        case ChatType::WHISPER: return "WHISPER";
        case ChatType::PARTY: return "PARTY";
        case ChatType::CLAN: return "CLAN";
        case ChatType::GM: return "GM";
        case ChatType::PETITION_PLAYER: return "PETITION_PLAYER";
        case ChatType::PETITION_GM: return "PETITION_GM";
        case ChatType::TRADE: return "TRADE";
        case ChatType::ALLIANCE: return "ALLIANCE";
        case ChatType::ANNOUNCEMENT: return "ANNOUNCEMENT";
        case ChatType::BOAT: return "BOAT";
        case ChatType::FRIEND: return "FRIEND";
        case ChatType::MSNCHAT: return "MSNCHAT";
        case ChatType::PARTYMATCH_ROOM: return "PARTYMATCH_ROOM";
        case ChatType::PARTYROOM_COMMANDER: return "PARTYROOM_COMMANDER";
        case ChatType::PARTYROOM_ALL: return "PARTYROOM_ALL";
        case ChatType::HERO_VOICE: return "HERO_VOICE";
        case ChatType::CRITICAL_ANNOUNCE: return "CRITICAL_ANNOUNCE";
        case ChatType::SCREEN_ANNOUNCE: return "SCREEN_ANNOUNCE";
        case ChatType::BATTLEFIELD: return "BATTLEFIELD";
        case ChatType::MPCC_ROOM: return "MPCC_ROOM";
        default: return "UNKNOWN";
    }
} 