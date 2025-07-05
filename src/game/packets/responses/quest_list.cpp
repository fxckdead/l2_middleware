// src/game/packets/responses/quest_list.cpp
#include "quest_list.hpp"
#include <iostream>

QuestList::QuestList(const Player* player)
    : player_(player)
{
    if (!player_) {
        throw std::invalid_argument("Player cannot be null for QuestList packet");
    }
    buildQuestList();
}

void QuestList::write(SendablePacketBuffer& buffer)
{
    // Packet structure: questCount + quests
    // Each quest: questId(4) + state(4)
    
    // Write quest count (2 bytes - matches L2J Mobius)
    buffer.writeInt16(static_cast<int16_t>(quests_.size()));
    
    // Write each quest
    for (const auto& quest : quests_)
    {
        buffer.writeInt32(static_cast<int32_t>(quest.questId));
        buffer.writeInt32(static_cast<int32_t>(quest.state));
    }
}

size_t QuestList::getSize() const
{
    // Calculate packet size: 2 bytes for count + 8 bytes per quest
    return 2 + (quests_.size() * 8);
}

void QuestList::buildQuestList()
{
    // For now, return empty quest list since we don't have a quest system implemented
    // TODO: Implement actual quest loading from database/player data
    quests_.clear();
    
    // Example quests (commented out for now):
    /*
    // Tutorial quest
    quests_.push_back({
        1,      // questId (Tutorial Quest)
        1       // state (active)
    });
    
    // First hunting quest
    quests_.push_back({
        2,      // questId (Hunt Wolves)
        1       // state (active)
    });
    
    // Available quest
    quests_.push_back({
        3,      // questId (Deliver Package)
        3       // state (available)
    });
    */
} 