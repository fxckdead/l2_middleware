#include "request_item_list.hpp"
#include <iostream>

void RequestItemList::read(ReadablePacketBuffer &buffer)
{
    // RequestItemList typically has no additional data beyond the opcode
    // Just consume any remaining bytes if present
    std::cout << "[RequestItemList] Client requesting inventory item list" << std::endl;
}

bool RequestItemList::isValid() const
{
    // Always valid - simple request packet
    return true;
}

std::string RequestItemList::toString() const
{
    return "RequestItemList [Client requesting inventory refresh]";
} 