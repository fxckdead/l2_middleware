#include "friend_list.hpp"
#include <iostream>

// Constructor
FriendList::FriendList(const Player* player)
    : player_(player)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for FriendList packet");
    }
    buildFriendList();
}

void FriendList::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class

    std::cout << "[FriendList] Sending friend list for: " << player_->getName() << std::endl;

    // Following L2J Mobius FriendList.java structure EXACTLY
    
    // 1. Friend count (int)
    buffer.writeUInt32(static_cast<uint32_t>(friends_.size()));
    
    // 2. Friend data
    for (const auto& friend_data : friends_)
    {
        buffer.writeUInt32(friend_data.objId); // character id
        buffer.writeCUtf16leString(friend_data.name); // character name
        buffer.writeUInt32(friend_data.online ? 1 : 0); // online status
        buffer.writeUInt32(friend_data.online ? friend_data.objId : 0); // object id if online
    }

    std::cout << "[FriendList] Friend list sent successfully (" << friends_.size() << " friends)" << std::endl;
}

size_t FriendList::getSize() const
{
    // Calculate packet size based on L2J Mobius structure
    size_t size = 1; // opcode

    // Fixed-size fields
    size += 4; // Friend count (int)
    
    // Friend data
    for (const auto& friend_data : friends_)
    {
        size += 4; // objId (int)
        size += (friend_data.name.length() + 1) * 2; // name (UTF-16LE + null)
        size += 4; // online status (int)
        size += 4; // online objId (int)
    }

    return size;
}

void FriendList::buildFriendList()
{
    // For now, return empty friend list since we don't have a friend system implemented
    // TODO: Implement actual friend loading from database/player data
    friends_.clear();
    
    // Example friends (commented out for now):
    /*
    // Online friend
    friends_.push_back({
        12345,           // objId
        "FriendName1",   // name
        true,            // online
        12345            // onlineObjId (same as objId when online)
    });
    
    // Offline friend
    friends_.push_back({
        67890,           // objId
        "FriendName2",   // name
        false,           // online
        0                // onlineObjId (0 when offline)
    });
    */
} 