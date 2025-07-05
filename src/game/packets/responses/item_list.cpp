#include "item_list.hpp"
#include <iostream>

// Constructor
ItemList::ItemList(const Player* player, bool showWindow)
    : player_(player), show_window_(showWindow)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for ItemList packet");
    }
}

void ItemList::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class

    std::cout << "[ItemList] Sending inventory for: " << player_->getName() 
              << " (show window: " << (show_window_ ? "yes" : "no") << ")" << std::endl;

    // Following L2J Mobius ItemList.java structure EXACTLY
    
    // 1. Show window flag (as short, not byte)
    buffer.writeUInt16(show_window_ ? 1 : 0);
    
    // 2. Item count (as short, not int)
    uint16_t item_count = 0; // TODO: Implement actual inventory system
    buffer.writeUInt16(item_count);
    
    // 3. Item data (none for now)
    // TODO: When inventory system is implemented, iterate through items:
    // for each item:
    //   - Object ID
    //   - Item ID  
    //   - Slot
    //   - Count
    //   - Enchant level
    //   - etc.
    // This will use writeItem() method similar to L2J Mobius

    std::cout << "[ItemList] Inventory sent successfully (" << item_count << " items)" << std::endl;
}

size_t ItemList::getSize() const
{
    // Calculate packet size based on L2J Mobius structure
    size_t size = 1; // opcode

    // Fixed-size fields (exactly like L2J Mobius)
    size += 2; // Show window flag (short)
    size += 2; // Item count (short)
    
    // Item data (none for now)
    // TODO: Add size calculation for actual items when inventory system is implemented

    return size;
} 