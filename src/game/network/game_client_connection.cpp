#include "game_client_connection.hpp"
#include "game_connection_manager.hpp"
#include "../packets/packet_factory.hpp"
#include "../packets/responses/ping_response.hpp"
#include "../packets/requests/no_op_packet.hpp"
#include "../packets/requests/protocol_version_packet.hpp"
#include "../packets/requests/auth_login_packet.hpp"
#include "../packets/requests/create_char_request_packet.hpp"
#include "../packets/responses/version_check_response.hpp"
#include "../packets/responses/character_selection_info.hpp"
#include "../packets/responses/new_character_success.hpp"
#include "../packets/responses/character_create_success.hpp"
#include "../server/game_server.hpp"
#include "../server/character_database_manager.hpp"

// =============================================================================
// Constructor
// =============================================================================

GameClientConnection::GameClientConnection(boost::asio::ip::tcp::socket socket,
                                           boost::asio::io_context &io_context,
                                           GameConnectionManager *manager)
    : BaseClientConnection(std::move(socket), io_context, manager)
{
    // Game client encryption will be initialized when we have a key
    // (after authentication with login server)

    log_connection_event("GameClientConnection created");
}

// =============================================================================
// State Management
// =============================================================================

void GameClientConnection::set_game_state(GameState new_state)
{
    GameState old_state = game_state_.load();

    if (!validate_game_state_transition(old_state, new_state))
    {
        log_connection_event("Invalid game state transition from " +
                             std::string(game_state_to_string(old_state)) +
                             " to " + std::string(game_state_to_string(new_state)));
        return;
    }

    game_state_.store(new_state);

    log_connection_event("Game state changed from " +
                         std::string(game_state_to_string(old_state)) +
                         " to " + std::string(game_state_to_string(new_state)));
}

// =============================================================================
// BaseClientConnection Implementation
// =============================================================================

void GameClientConnection::handle_complete_packet(std::vector<uint8_t> packet_data)
{
    try
    {
        if (packet_data.empty())
        {
            log_connection_event("Received empty packet");
            return;
        }

        uint8_t actual_opcode = 0; // will set after decrypt

        // Debug logging - DETAILED VALIDATION
        log_connection_event("=== PACKET VALIDATION - BEFORE DECRYPT ===");
        log_connection_event("Packet size: " + std::to_string(packet_data.size()) + " bytes");

        std::string hex_dump = "Raw (first 32 bytes): ";
        for (size_t i = 0; i < std::min(packet_data.size(), size_t(32)); ++i)
        {
            char hex_byte[4];
            snprintf(hex_byte, sizeof(hex_byte), "%02X ", packet_data[i]);
            hex_dump += hex_byte;
        }
        log_connection_event(hex_dump);

        // CRITICAL DEBUG: Check packet data source
        if (packet_data.size() >= 2)
        {
            uint16_t first_two = static_cast<uint16_t>(packet_data[0]) |
                                 (static_cast<uint16_t>(packet_data[1]) << 8);
            log_connection_event("CRITICAL: First 2 bytes interpreted as length: " + std::to_string(first_two));
            log_connection_event("CRITICAL: This should be ENCRYPTED PAYLOAD, not length!");
            log_connection_event("CRITICAL: If seeing huge numbers (>1000), header stripping failed!");
        }

        // Decrypt the packet
        if (!decrypt_incoming_packet(packet_data))
        {
            log_connection_event("Failed to decrypt incoming packet");
            force_disconnect();
            return;
        }

        // After successful decryption, refresh opcode
        actual_opcode = packet_data[0];

        // Debug logging after decryption - DETAILED VALIDATION
        log_connection_event("=== PACKET VALIDATION - AFTER DECRYPT ===");
        log_connection_event("Decrypted size: " + std::to_string(packet_data.size()) + " bytes");
        log_connection_event("Opcode (first byte): 0x" +
                             std::string(1, "0123456789ABCDEF"[actual_opcode >> 4]) +
                             std::string(1, "0123456789ABCDEF"[actual_opcode & 0xF]));

        hex_dump = "Decrypted (first 32 bytes): ";
        for (size_t i = 0; i < std::min(packet_data.size(), size_t(32)); ++i)
        {
            char hex_byte[4];
            snprintf(hex_byte, sizeof(hex_byte), "%02X ", packet_data[i]);
            hex_dump += hex_byte;
        }
        log_connection_event(hex_dump);

        // Special validation for 0x0B (CreateCharacter)
        if (actual_opcode == 0x0B && packet_data.size() >= 20)
        {
            // Try reading UTF-16LE name starting at different offsets
            for (int offset = 1; offset <= 10 && offset < packet_data.size() - 1; offset++)
            {
                std::wstring wide_name;

                // Try to read up to 7 characters (14 bytes) as UTF-16LE
                for (int i = 0; i < 7 && (offset + i * 2 + 1) < packet_data.size(); i++)
                {
                    uint16_t wide_char = static_cast<uint16_t>(packet_data[offset + i * 2]) |
                                         (static_cast<uint16_t>(packet_data[offset + i * 2 + 1]) << 8);

                    if (wide_char == 0)
                        break; // null terminator
                    if (wide_char < 32 || wide_char > 126)
                        break; // non-printable

                    wide_name += static_cast<wchar_t>(wide_char);
                }

                // Convert to narrow string for logging
                std::string narrow_name(wide_name.begin(), wide_name.end());
                log_connection_event("Character create request: " + narrow_name);
            }
        }

        // Use GamePacketFactory to create and handle packets
        try
        {
            auto packet = GamePacketFactory::createFromClientData(packet_data);
            if (packet)
            {
                handle_game_packet(std::move(packet), actual_opcode, packet_data);
            }
            else
            {
                log_connection_event("Failed to create packet from data");
            }
        }
        catch (const PacketException &e)
        {
            log_connection_event("Packet creation error: " + std::string(e.what()));
            // Continue processing other packets - don't disconnect for unknown packets
        }
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error handling packet: " + std::string(e.what()));
        force_disconnect();
    }
}

bool GameClientConnection::validate_state_transition(State from, State to) const
{
    // Basic state transition validation (can be extended)
    switch (from)
    {
    case State::CONNECTED:
        return to == State::DISCONNECTED; // Can only disconnect from connected
    case State::DISCONNECTED:
        return false; // Can't transition from disconnected
    default:
        return false;
    }
}

// =============================================================================
// Encryption Implementation
// =============================================================================

bool GameClientConnection::decrypt_incoming_packet(std::vector<uint8_t> &packet_data)
{
    try
    {
        if (game_encryption_)
        {
            return game_encryption_->decrypt(packet_data, false); // Base connection already stripped header
        }
        else if (blowfish_encryption_)
        {
            return blowfish_encryption_->decrypt(packet_data);
        }
        // If no encryption is set up yet, packets are in plaintext
        return true;
    }
    catch (const std::exception &e)
    {
        log_connection_event("Decryption error: " + std::string(e.what()));
        return false;
    }
}

void GameClientConnection::encrypt_outgoing_packet(std::vector<uint8_t> &packet_data)
{
    try
    {
        // DEBUG: Log encryption state
        static int packet_count = 0;
        packet_count++;

        if (game_encryption_)
        {
            log_connection_event("ENCRYPT PACKET #" + std::to_string(packet_count) + " - XOR - Size: " + std::to_string(packet_data.size()) + " bytes");
            game_encryption_->encrypt(packet_data, false); // Header already stripped by prepare_packet_for_transmission
        }
        else if (blowfish_encryption_)
        {
            log_connection_event("ENCRYPT PACKET #" + std::to_string(packet_count) + " - BLOWFISH - Size: " + std::to_string(packet_data.size()) + " bytes");
            blowfish_encryption_->encrypt(packet_data);
        }
        // If no encryption is set up yet, packets are sent in plaintext
        else
        {
            log_connection_event("Encrypting packet in plaintext mode (encryption not initialized)");
        }
    }
    catch (const std::exception &e)
    {
        log_connection_event("Encryption error: " + std::string(e.what()));
    }
}

// =============================================================================
// Game-Specific State Validation
// =============================================================================

bool GameClientConnection::validate_game_state_transition(GameState from, GameState to) const
{
    // Define valid game state transitions
    switch (from)
    {
    case GameState::CONNECTED:
        return to == GameState::AUTHENTICATED || to == GameState::DISCONNECTED;
    case GameState::AUTHENTICATED:
        return to == GameState::IN_GAME || to == GameState::DISCONNECTED;
    case GameState::IN_GAME:
        return to == GameState::DISCONNECTED;
    case GameState::DISCONNECTED:
        return false; // Can't transition from disconnected
    default:
        return false;
    }
}

// =============================================================================
// Game Packet Handling
// =============================================================================

void GameClientConnection::handle_game_packet(std::unique_ptr<ReadablePacket> packet, uint8_t actual_opcode, const std::vector<uint8_t> &raw_packet_data)
{
    if (!packet)
    {
        log_connection_event("Received null packet");
        return;
    }

    try
    {
        // Log the actual opcode for debugging
        char hex_opcode[8];
        snprintf(hex_opcode, sizeof(hex_opcode), "0x%02X", actual_opcode);
        log_connection_event("Processing game packet opcode: " + std::string(hex_opcode) +
                             " in state: " + std::string(game_state_to_string(game_state_.load())));

        // Handle Interlude Update 3 packets based on correct opcodes
        switch (actual_opcode)
        {
        case 0x00: // SendProtocolVersion
            handle_protocol_version_packet(packet);
            break;
        case 0x01: // MoveBackwardToLocation
            log_connection_event("MoveBackwardToLocation packet received");
            break;
        case 0x02: // Say (chat)
            log_connection_event("Say packet received");
            break;
        case 0x03: // RequestEnterWorld
            log_connection_event("RequestEnterWorld packet received");
            break;
        case 0x04: // Action (not unknown - this is an action packet!)
            log_connection_event("Action packet received (attack, pickup, etc)");
            break;
        case 0x08: // RequestLogin (actual login packet!)
            handle_request_login_packet(packet);
            break;
        case 0x09: // SendLogOut
            log_connection_event("SendLogOut packet received");
            break;
        case 0x0A: // RequestAttack (not unknown - this is attack!)
            log_connection_event("RequestAttack packet received");
            break;
        case 0x0B: // RequestCharacterCreate - Packet to create a new character in database/memory
            log_connection_event("RequestCharacterCreate packet received - using proper parser");
            handle_character_create_packet(packet);
            break;
        case 0x0C: // RequestCharacterDelete
            log_connection_event("RequestCharacterDelete packet received");
            break;
        case 0x0D: // RequestGameStart (character selection)
            log_connection_event("RequestGameStart packet received");
            break;
        case 0x0E: // RequestNewCharacter - Packet to show the character creation screen
            handle_request_new_character_packet(packet);
            break;
        default:
            char hex_unknown[8];
            snprintf(hex_unknown, sizeof(hex_unknown), "0x%02X", actual_opcode);
            log_connection_event("Received unknown packet opcode: " + std::string(hex_unknown));
            break;
        }

        log_connection_event("Game packet processed successfully");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error processing game packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_no_op_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        // Cast to NoOpPacket to access ping data
        auto *ping_packet = dynamic_cast<const NoOpPacket *>(packet.get());
        if (!ping_packet)
        {
            log_connection_event("Failed to cast packet to NoOpPacket");
            return;
        }

        const auto &ping_data = ping_packet->getPingData();

        // Log the ping request with data size
        log_connection_event("Ping packet received with " + std::to_string(ping_data.size()) + " bytes of data");

        // Create and send ping response (echo back the same data)
        auto ping_response = std::make_unique<PingResponse>(ping_data);
        send_packet(std::move(ping_response));

        log_connection_event("Ping response sent successfully");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error handling ping packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_protocol_version_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        // Cast to ProtocolVersionPacket to access version data
        auto *protocol_packet = dynamic_cast<const ProtocolVersionPacket *>(packet.get());
        if (!protocol_packet)
        {
            log_connection_event("Failed to cast packet to ProtocolVersionPacket");
            return;
        }

        int32_t client_version = protocol_packet->getClientProtocolVersion();
        log_connection_event("Client protocol version: " + std::to_string(client_version));

        // For Interlude Update 3, we accept the protocol
        // TODO: Add proper version validation if needed
        bool protocol_accepted = true;

        if (protocol_accepted)
        {
            // Generate/use the dynamic encryption key
            std::vector<uint8_t> game_key = {
                0x94, 0x35, 0x00, 0x00, 0xa1, 0x6c, 0x54, 0x87,
                0x45, 0xa3, 0x7a, 0x86, 0xf0, 0x33, 0x40, 0x64};

            // Create and send VersionCheck response *without* encryption. The client
            // must be able to read this packet in plain‐text so it can extract the
            // Blowfish key that will be used for all subsequent communication.
            auto version_response = std::make_unique<VersionCheckResponse>(protocol_accepted, game_key, 0);

            // Serialize WITHOUT padding (withPadding=false) so the packet size
            // exactly matches the client expectation (27-byte payload).
            auto raw_data = version_response->serialize(false, 1);

            // Send raw – this path will still add the 2-byte length header and
            // performs no encryption because none is initialised yet.
            send_raw_packet(raw_data);

            log_connection_event("VersionCheck response sent in PLAINTEXT with encryption key - protocol accepted");

            // Now that the key is safely delivered we can enable Blowfish so the
            // very next client packet (0x08 RequestLogin) will be decrypted
            // correctly.
            initialize_encryption(game_key);

            if (blowfish_encryption_)
            {
                log_connection_event("Game client BLOWFISH encryption ENABLED for subsequent packets");
            }
        }
        else
        {
            // Send rejection response
            auto version_response = std::make_unique<VersionCheckResponse>(protocol_accepted);
            send_packet(std::move(version_response));
            log_connection_event("VersionCheck response sent - protocol rejected");
        }
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error handling protocol version packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_request_login_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        // Cast to AuthLoginPacket to access session data
        auto *login_packet = dynamic_cast<const AuthLoginPacket *>(packet.get());
        if (!login_packet)
        {
            log_connection_event("Failed to cast packet to AuthLoginPacket");
            return;
        }

        // TODO: Extract session keys from the packet
        // For now, fake validation - always accept login
        std::string username = "TestPlayer"; // Should come from packet

        log_connection_event("RequestLogin received for user: " + username);
        log_connection_event("Session validation: ACCEPTED (fake validation for now)");

        // Store player info (fake data for now)
        player_name_ = username;

        // Update game state to authenticated
        set_game_state(GameState::AUTHENTICATED);

        // Send CharacterSelectionInfo from database
        auto *char_db = getCharacterDatabaseManager();
        if (!char_db) {
            log_connection_event("ERROR: Character database manager not available during login");
            return;
        }
        auto char_select_packet = CharacterSelectionInfo::createFromDatabase(char_db, username);

        log_connection_event("Sending CharacterSelectionInfo with " +
                             std::to_string(char_db ? char_db->getCharacterCountForAccount(username) : 0) +
                             " characters for account: " + username);

        send_packet(std::move(char_select_packet));

        log_connection_event("Game server authentication successful - CharacterSelectionInfo sent");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error handling RequestLogin packet: " + std::string(e.what()));
        // TODO: Send login failure response
    }
}

void GameClientConnection::handle_character_create_raw_data(const std::vector<uint8_t> &packet_data)
{
    log_connection_event("=== CHARACTER CREATE - RAW DATA CAPTURE ===");
    log_connection_event("Packet size: " + std::to_string(packet_data.size()) + " bytes");

    // Log full hex dump for analysis
    std::string hex_dump = "HEX: ";
    for (size_t i = 0; i < packet_data.size() && i < 128; ++i)
    {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X ", packet_data[i]);
        hex_dump += hex;

        // Add line breaks every 16 bytes for readability
        if ((i + 1) % 16 == 0)
        {
            log_connection_event(hex_dump);
            hex_dump = "     ";
        }
    }
    if (!hex_dump.empty() && hex_dump != "     ")
    {
        log_connection_event(hex_dump);
    }

    // Try to parse typical character creation fields for analysis
    log_connection_event("ANALYSIS ATTEMPT:");
    if (packet_data.size() >= 8)
    {
        log_connection_event("First 8 bytes: " +
                             std::to_string(packet_data[0]) + " " + std::to_string(packet_data[1]) + " " +
                             std::to_string(packet_data[2]) + " " + std::to_string(packet_data[3]) + " " +
                             std::to_string(packet_data[4]) + " " + std::to_string(packet_data[5]) + " " +
                             std::to_string(packet_data[6]) + " " + std::to_string(packet_data[7]));
    }

    log_connection_event("=== USE THESE VALUES IN CharacterSelectionInfo TO AVOID CRASH! ===");
}

void GameClientConnection::handle_character_create_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        auto *create_packet = dynamic_cast<const CreateCharRequestPacket *>(packet.get());
        if (!create_packet)
        {
            log_connection_event("Failed to cast packet to CreateCharRequestPacket");
            return;
        }

        // Log key character data
        log_connection_event("Character create request: " + create_packet->toString());

        // Basic validation
        if (!create_packet->isValid())
        {
            log_connection_event("Character creation validation failed");
            return;
        }

        // Get character database manager
        auto *char_db = getCharacterDatabaseManager();
        if (!char_db)
        {
            log_connection_event("Character database manager not available");
            return;
        }

        // Create character in database
        uint32_t character_id = char_db->createCharacter(
            player_name_, // account name
            create_packet->getCharacterName(),
            create_packet->getRace(),
            create_packet->getSex(),
            create_packet->getClassId(),
            create_packet->getHairStyle(),
            create_packet->getHairColor(),
            create_packet->getFace());

        if (character_id == 0)
        {
            log_connection_event("Character creation failed - character name might already exist or account full");
            // TODO: Send character creation failure response
            return;
        }

        log_connection_event("Character created successfully with ID: " + std::to_string(character_id));

        // Send success response
        auto success_response = std::make_unique<CharacterCreateSuccess>();
        send_packet(std::move(success_response));

        log_connection_event("CharacterCreateSuccess response sent");

        // Send updated character list to show the new character
        auto char_list_response = CharacterSelectionInfo::createFromDatabase(char_db, player_name_);
        send_packet(std::move(char_list_response));

        log_connection_event("Updated CharacterSelectionInfo sent with " +
                             std::to_string(char_db->getCharacterCountForAccount(player_name_)) +
                             " characters for account: " + player_name_);
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error processing character creation packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_request_new_character_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    log_connection_event("RequestNewCharacter packet received - showing character creation screen");
    try
    {
        auto create_ok_response = std::make_unique<NewCharacterSuccess>();
        send_packet(std::move(create_ok_response));
        log_connection_event("NewCharacterSuccess response sent - client UI should update");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error sending NewCharacterSuccess response: " + std::string(e.what()));
    }
}

// =============================================================================
// Encryption Management
// =============================================================================

// Override send_packet to use 8-byte padding for Blowfish (Game Server specific)
void GameClientConnection::send_packet(std::unique_ptr<SendablePacket> packet)
{
    if (!is_connected() || !packet)
    {
        return;
    }

    try
    {
        // Choose padding based on active encryption: XOR uses 4-byte blocks, Blowfish needs 8
        size_t align = game_encryption_ ? 4 : 8;
        auto packet_data = packet->serialize(true, align);
        log_connection_event("DEBUG: Game packet serialized with " + std::to_string(align) + "-byte padding: " + std::to_string(packet_data.size()) + " bytes");
        send_raw_packet(packet_data);
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error serializing game packet: " + std::string(e.what()));
        force_disconnect();
    }
}

void GameClientConnection::initialize_encryption(const std::vector<uint8_t> &dynamic_key)
{
    try
    {
        // The client concatenates the 8-byte dynamic part you send in VersionCheck
        // with an 8-byte static tail hard-coded in the executable.  If we keep
        // sending the full 16-byte dynamic_key as-is, bytes 8-15 never match
        // the client expectation and decryption breaks after the first block.

        static const std::array<uint8_t, 8> STATIC_TAIL = {
            0xC8, 0x27, 0x93, 0x01, 0xA1, 0x6C, 0x31, 0x97};

        if (dynamic_key.size() < 8)
        {
            throw std::runtime_error("Dynamic key must be at least 8 bytes");
        }

        std::vector<uint8_t> full_key(16);
        // First 8 bytes come from the dynamic part sent in VersionCheck
        std::copy(dynamic_key.begin(), dynamic_key.begin() + 8, full_key.begin());
        // Last 8 bytes are the static client constant
        std::copy(STATIC_TAIL.begin(), STATIC_TAIL.end(), full_key.begin() + 8);

        game_encryption_ = std::make_unique<GameClientEncryption>(full_key);
        game_encryption_->enable(); // ensure first encrypted packet is handled correctly

        // Optional fallback: clear Blowfish (our current client uses XOR)
        blowfish_encryption_.reset();

        log_connection_event("Game client XOR encryption ENABLED (dynamic+static key)");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Failed to initialize encryption: " + std::string(e.what()));
    }
}

CharacterDatabaseManager *GameClientConnection::getCharacterDatabaseManager() const
{
    // Access the character database manager through the global game server instance
    extern GameServer *g_game_server_instance;
    if (g_game_server_instance)
    {
        return g_game_server_instance->get_character_database_manager();
    }
    return nullptr;
}

// =============================================================================
// Disconnect Handling
// =============================================================================

void GameClientConnection::on_disconnect()
{
    log_connection_event("Game client disconnected: " + player_name_);
    set_game_state(GameState::DISCONNECTED);
}

// =============================================================================
// Utility Functions
// =============================================================================

const char *game_state_to_string(GameClientConnection::GameState state)
{
    switch (state)
    {
    case GameClientConnection::GameState::CONNECTED:
        return "CONNECTED";
    case GameClientConnection::GameState::AUTHENTICATED:
        return "AUTHENTICATED";
    case GameClientConnection::GameState::IN_GAME:
        return "IN_GAME";
    case GameClientConnection::GameState::DISCONNECTED:
        return "DISCONNECTED";
    default:
        return "UNKNOWN";
    }
}