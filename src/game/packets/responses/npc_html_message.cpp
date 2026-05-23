#include "npc_html_message.hpp"
#include <iostream>

// Default constructor
NpcHtmlMessage::NpcHtmlMessage()
    : npc_obj_id_(0)
    , html_content_("")
    , item_id_(0)
{
}

// Constructor with NPC object ID
NpcHtmlMessage::NpcHtmlMessage(uint32_t npcObjId)
    : npc_obj_id_(npcObjId)
    , html_content_("")
    , item_id_(0)
{
}

// Constructor with HTML content
NpcHtmlMessage::NpcHtmlMessage(const std::string& html)
    : npc_obj_id_(0)
    , html_content_(html)
    , item_id_(0)
{
}

// Constructor with NPC object ID and HTML content
NpcHtmlMessage::NpcHtmlMessage(uint32_t npcObjId, const std::string& html)
    : npc_obj_id_(npcObjId)
    , html_content_(html)
    , item_id_(0)
{
}

// Constructor with NPC object ID and item ID
NpcHtmlMessage::NpcHtmlMessage(uint32_t npcObjId, uint32_t itemId)
    : npc_obj_id_(npcObjId)
    , html_content_("")
    , item_id_(itemId)
{
    if (itemId < 0)
    {
        throw std::invalid_argument("Item ID cannot be negative");
    }
}

// Constructor with NPC object ID, item ID, and HTML content
NpcHtmlMessage::NpcHtmlMessage(uint32_t npcObjId, uint32_t itemId, const std::string& html)
    : npc_obj_id_(npcObjId)
    , html_content_(html)
    , item_id_(itemId)
{
    if (itemId < 0)
    {
        throw std::invalid_argument("Item ID cannot be negative");
    }
}

uint8_t NpcHtmlMessage::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> NpcHtmlMessage::getExPacketId() const
{
    return std::nullopt;
}

void NpcHtmlMessage::write(SendablePacketBuffer &buffer)
{
    // Write packet structure matching L2J Mobius exactly:
    // 1. NPC object ID
    buffer.writeUInt32(npc_obj_id_);
    
    // 2. HTML content as string
    buffer.writeCUtf16leString(html_content_);
    
    // 3. Item ID
    buffer.writeUInt32(item_id_);
    
    std::cout << "[NpcHtmlMessage] Sending HTML message - NPC ID: " << npc_obj_id_ 
              << ", Item ID: " << item_id_ 
              << ", Content: " << html_content_ << std::endl;
}

size_t NpcHtmlMessage::getSize() const
{
    // Calculate packet size: opcode + npc_obj_id + html_content + item_id
    size_t size = 1; // opcode
    size += 4; // npc_obj_id (uint32)
    size += (html_content_.length() + 1) * 2; // html_content (UTF-16LE + null terminator)
    size += 4; // item_id (uint32)
    return size;
} 