#include "send_macro_list.hpp"
#include <iostream>

// Constructor
SendMacroList::SendMacroList(uint32_t revision) : m_revision(revision)
{
}

void SendMacroList::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class
    
    std::cout << "[SendMacroList] Sending empty macro list (revision: " << m_revision << ")" << std::endl;
    
    // Following L2J Mobius SendMacroList.java structure EXACTLY
    
    // 1. Macro change revision (changes after each macro edition)
    buffer.writeUInt32(m_revision);
    
    // 2. Unknown byte (always 0)
    buffer.writeUInt8(0);
    
    // 3. Count of macros (0 for empty list)
    buffer.writeUInt8(0);
    
    // 4. Macro data follows flag (0 = no macro data)
    buffer.writeUInt8(0);
    
    // TODO: When implementing full macro system, this would be:
    // if (macro != nullptr) {
    //     buffer.writeUInt32(macro->id);
    //     buffer.writeCUtf16leString(macro->name);
    //     buffer.writeCUtf16leString(macro->descr);
    //     buffer.writeCUtf16leString(macro->acronym);
    //     buffer.writeUInt8(macro->icon);
    //     buffer.writeUInt8(macro->commands.size());
    //     // ... serialize commands
    // }
}

size_t SendMacroList::getSize() const
{
    // Packet ID (1) + revision (4) + unknown (1) + count (1) + flag (1) = 8 bytes
    return 8;
} 