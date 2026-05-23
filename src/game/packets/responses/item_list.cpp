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
    // Following L2J Mobius ItemList.java structure EXACTLY:
    // buffer.writeShort(_showWindow);
    // buffer.writeShort(_items.size());
    // for (Item item : _items) { writeItem(item, buffer); }

    std::cout << "[ItemList] Sending inventory for: " << player_->getName() 
              << " (show window: " << (show_window_ ? "yes" : "no") << ")" << std::endl;

    // 1. Show window flag (matches L2J: buffer.writeShort(_showWindow))
    buffer.writeUInt16(show_window_ ? 1 : 0);
    
    // 2. Item count (matches L2J: buffer.writeShort(_items.size()))
    uint16_t item_count = 0; // Empty inventory for now
    buffer.writeUInt16(item_count);
    
    // 3. Item data - for each item, L2J calls writeItem() which writes:
    // Based on AbstractItemPacket.writeItem():
    // buffer.writeShort(item.getItem().getType1());        // Item type 1
    // buffer.writeInt(item.getObjectId());                 // Object ID
    // buffer.writeInt(item.getItem().getDisplayId());      // Item ID
    // buffer.writeInt(item.getCount());                    // Quantity
    // buffer.writeShort(item.getItem().getType2());        // Item type 2
    // buffer.writeShort(item.getCustomType1());            // Custom type 1 (always 0)
    // buffer.writeShort(item.getEquipped());               // Equipped flag
    // buffer.writeInt(item.getItem().getBodyPart());       // Body part slot
    // buffer.writeShort(item.getEnchant());                // Enchant level
    // buffer.writeShort(item.getCustomType2());            // Custom type 2
    // buffer.writeInt(item.getAugmentationBonus());        // Augmentation
    // buffer.writeInt(item.getMana());                     // Mana
    
    // TODO: When inventory system is implemented, iterate through items and call writeItem()
    
    std::cout << "[ItemList] Inventory sent successfully (" << item_count << " items)" << std::endl;
}

size_t ItemList::getSize() const
{
    // Calculate packet size based on L2J Mobius structure
    // Note: Opcode is handled by base class, not included here
    
    size_t size = 0;
    
    // Fixed-size fields (exactly like L2J Mobius)
    size += 2; // Show window flag (short)
    size += 2; // Item count (short)
    
    // Item data size calculation (based on AbstractItemPacket.writeItem())
    // Each item is 38 bytes total:
    // - Type1 (2) + ObjectId (4) + ItemId (4) + Count (4) + Type2 (2)
    // - CustomType1 (2) + Equipped (2) + BodyPart (4) + Enchant (2)
    // - CustomType2 (2) + Augmentation (4) + Mana (4) = 38 bytes per item
    
    uint16_t item_count = 0; // Empty inventory for now
    size += item_count * 38; // 38 bytes per item (L2J structure)
    
    return size;
} 