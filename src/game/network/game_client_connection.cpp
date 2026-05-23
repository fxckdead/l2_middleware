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
#include "../packets/responses/character_selected.hpp"
#include "../packets/responses/user_info.hpp"
#include "../packets/responses/validate_location.hpp"
#include "../packets/responses/item_list.hpp"
#include "../packets/responses/skill_cool_time.hpp"
#include "../packets/responses/shortcut_init.hpp"
#include "../packets/responses/etc_status_update.hpp"
#include "../packets/responses/ex_storage_max_count.hpp"
#include "../packets/responses/quest_list.hpp"
// Phase 3: Social/Clan packets
#include "../packets/responses/henna_info.hpp"
#include "../packets/responses/pledge_skill_list.hpp"
#include "../packets/responses/friend_list.hpp"
#include "../packets/responses/pledge_show_member_list_all.hpp"
#include "../packets/responses/pledge_status_changed.hpp"
// Phase 4: Welcome/System packets
#include "../packets/responses/system_message.hpp"
#include "../packets/responses/ex_show_screen_message.hpp"
#include "../packets/responses/action_failed.hpp"
#include "../packets/responses/skill_list.hpp"
#include "../packets/responses/status_update.hpp"
#include "../packets/responses/char_info.hpp"
#include "../packets/responses/show_mini_map.hpp"
#include "../packets/responses/send_macro_list.hpp"
#include "../packets/responses/move_to_location.hpp"
#include "../packets/responses/ex_set_compass_zone_code.hpp"
#include "../packets/responses/creature_say.hpp"
#include "../packets/responses/npc_info.hpp"
#include "../packets/responses/abnormal_status_update.hpp"

#include "../packets/requests/enter_world_packet.hpp"
#include "../packets/requests/request_game_start.hpp"
#include "../packets/requests/move_backward_to_location_packet.hpp"
#include "../packets/requests/validate_position_packet.hpp"
#include "../entities/player.hpp"
#include "../server/game_server.hpp"
#include "../server/character_database_manager.hpp"
#include <chrono>

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

        // Decrypt the packet
        if (!decrypt_incoming_packet(packet_data))
        {
            log_connection_event("Failed to decrypt incoming packet");
            force_disconnect();
            return;
        }

        // Extract opcode after decryption
        uint8_t opcode = packet_data[0];

        // Use GamePacketFactory to create and handle packets
        try
        {
            auto packet = GamePacketFactory::createFromClientData(packet_data);
            if (packet)
            {
                handle_game_packet(std::move(packet), opcode, packet_data);
            }
            else
            {
                log_connection_event("Failed to create packet from data");
            }
        }
        catch (const PacketException &e)
        {
            log_connection_event("Packet creation error: " + std::string(e.what()));
            log_connection_event("CRITICAL: Client may be waiting for response to unknown packet - this could cause loading screen hang");
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
        if (game_encryption_)
        {
            game_encryption_->encrypt(packet_data, false); // Header already stripped by prepare_packet_for_transmission
        }
        else if (blowfish_encryption_)
        {
            blowfish_encryption_->encrypt(packet_data);
        }
        // If no encryption is set up yet, packets are sent in plaintext
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
        // Log packet processing with enhanced details
        char hex_opcode[8];
        snprintf(hex_opcode, sizeof(hex_opcode), "0x%02X", actual_opcode);
        log_connection_event("=== PROCESSING PACKET " + std::string(hex_opcode) +
                             " in state: " + std::string(game_state_to_string(game_state_.load())) + " ===");
        
        // Log packet size and timing for debugging loading screen hang
        log_connection_event("Packet size: " + std::to_string(raw_packet_data.size()) + " bytes");

        // Handle Interlude Update 3 packets based on correct opcodes
        switch (actual_opcode)
        {
        case 0x00: // SendProtocolVersion
            handle_protocol_version_packet(packet);
            break;
        case 0x01: // MoveBackwardToLocation
            handle_move_backward_to_location_packet(packet);
            break;
        case 0x38: // Say2 (chat)
            log_connection_event("Say2 packet received");
            break;
        case 0x03: // RequestEnterWorld
            handle_enter_world_packet(packet);
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
            handle_character_create_packet(packet);
            break;
        case 0x0C: // RequestCharacterDeletePacket
            log_connection_event("RequestCharacterDeletePacket packet received");
            break;
        case 0x0D: // RequestGameStart (character selection)
            handle_request_game_start_packet(packet);
            break;
        case 0x0E: // RequestNewCharacter - Packet to show the character creation screen
            handle_request_new_character_packet(packet);
            break;
        case 0x0F: // RequestItemList - Client requesting inventory item list
            handle_request_item_list_packet(packet);
            break;
        case 0x25: // RequestAnswerJoinPledge
            handle_request_answer_join_pledge_packet(packet);
            break;
        case 0x48: // ValidatePosition - client position update for reconciliation
            handle_validate_position_packet(packet);
            break;
        case 0x9D: // RequestSkillCoolTime
            handle_request_skill_cool_time_packet(packet);
            break;
        case 0xCD: // RequestShowMiniMap
            handle_request_show_mini_map_packet(packet);
            break;
        case 0xD0: // Extended packets (already handled by packet factory, but log here)
            log_connection_event("Extended packet processed by factory");
            // Check if this is a RequestManorList packet
            if (auto* manor_packet = dynamic_cast<const RequestManorList*>(packet.get())) {
                handle_request_manor_list_packet(packet);
            }
            break;
        default:
            char hex_unknown[8];
            snprintf(hex_unknown, sizeof(hex_unknown), "0x%02X", actual_opcode);
            log_connection_event("*** UNKNOWN PACKET OPCODE: " + std::string(hex_unknown) + " ***");
            log_connection_event("*** CRITICAL: Client may be waiting for response - THIS COULD CAUSE LOADING SCREEN HANG ***");
            log_connection_event("Packet data size: " + std::to_string(raw_packet_data.size()) + " bytes");
            
            // Log first few bytes of unknown packet for debugging
            if (raw_packet_data.size() > 0) {
                std::string hex_data = "";
                for (size_t i = 0; i < std::min(raw_packet_data.size(), size_t(16)); ++i) {
                    char hex_byte[4];
                    snprintf(hex_byte, sizeof(hex_byte), "%02X ", raw_packet_data[i]);
                    hex_data += hex_byte;
                }
                log_connection_event("First 16 bytes: " + hex_data);
            }
            break;
        }
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
        if (!char_db)
        {
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
// This uses the 0x0D opcode => SelectCharPacket
void GameClientConnection::handle_request_game_start_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        auto *game_start_packet = dynamic_cast<const RequestGameStart *>(packet.get());
        if (!game_start_packet)
        {
            log_connection_event("Failed to cast packet to RequestGameStart");
            return;
        }

        // Validate the packet
        if (!game_start_packet->isValid())
        {
            log_connection_event("Invalid RequestGameStart packet received");
            return;
        }

        // Get the character object ID from the packet
        int32_t character_id = game_start_packet->getCharacterObjectId();
        log_connection_event("RequestGameStart received for character ID: " + std::to_string(character_id));

        // Get character database manager
        auto *char_db = getCharacterDatabaseManager();
        if (!char_db)
        {
            log_connection_event("Character database manager not available");
            return;
        }

        // Verify the character exists and belongs to this account
        auto character_info = char_db->getCharacterBySlot(player_name_, static_cast<uint32_t>(character_id));
        if (!character_info)
        {
            log_connection_event("Character ID " + std::to_string(character_id) + " not found in database");
            return;
        }

        // Verify the character belongs to this player's account
        if ((*character_info)->getAccountName() != player_name_)
        {
            log_connection_event("Character ID " + std::to_string(character_id) +
                                 " does not belong to account: " + player_name_);
            return;
        }

        // Character validation successful - store the selected character
        set_character_id(static_cast<uint32_t>(character_id));

        log_connection_event("Character '" + (*character_info)->getName() + "' (ID: " +
                             std::to_string(character_id) + ") selected for account: " + player_name_);

        // Send CharSelected response packet to confirm character selection
        auto char_selected_response = std::make_unique<CharacterSelected>(*character_info, session_id_);
        send_packet(std::move(char_selected_response));

        log_connection_event("CharSelected response sent for character: " + (*character_info)->getName());

        // Transition to IN_GAME state
        set_game_state(GameState::IN_GAME);
        log_connection_event("Character selection successful - player now IN_GAME");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error processing RequestGameStart packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_enter_world_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        auto *enter_world_packet = dynamic_cast<const EnterWorldPacket *>(packet.get());
        if (!enter_world_packet)
        {
            log_connection_event("Failed to cast packet to EnterWorldPacket");
            return;
        }

        // Validate the packet
        if (!enter_world_packet->isValid())
        {
            log_connection_event("Invalid EnterWorld packet received");
            return;
        }

        log_connection_event("EnterWorld packet received: " + enter_world_packet->toString());

        // Verify player is in correct state
        if (!is_game_state(GameState::IN_GAME))
        {
            log_connection_event("EnterWorld received but player not in IN_GAME state");
            return;
        }

        // Verify character is selected
        if (character_id_ < 0)
        {
            log_connection_event("EnterWorld received but no character selected");
            return;
        }

        log_connection_event("Player entering world - character ID: " + std::to_string(character_id_));

        // Get character data for spawning
        auto *char_db = getCharacterDatabaseManager();
        if (!char_db)
        {
            log_connection_event("Character database manager not available during EnterWorld");
            return;
        }

        auto character_info = char_db->getCharacterBySlot(player_name_, character_id_);
        if (!character_info)
        {
            log_connection_event("Character not found during EnterWorld - ID: " + std::to_string(character_id_));
            return;
        }

        log_connection_event("*** STARTING ENTER WORLD SEQUENCE FOR: " + (*character_info)->getName() + " ***");
        log_connection_event("*** EXPECTED CLIENT BEHAVIOR: Loading screen should disappear after ActionFailed packet ***");

        // EnterWorld spawn sequence, ported from L2J Mobius EnterWorld.java (Interlude).
        // World-dependent packets (CharInfo/NpcInfo via spawnMe, zone packets) are
        // intentionally omitted until a world system exists - the client clears the
        // loading screen on the final ActionFailed regardless.
        const Player *player = *character_info;

        // Welcome system message id 34 = WELCOME_TO_THE_WORLD_OF_LINEAGE_II
        static constexpr int32_t SM_WELCOME_TO_LINEAGE_II = 34;

        struct NamedPacket
        {
            const char *name;
            std::unique_ptr<SendablePacket> packet;
        };

        std::array<NamedPacket, 15> spawn_sequence{{
            {"UserInfo", std::make_unique<UserInfo>(player)},                                 // EnterWorld.java:167
            {"SendMacroList", std::make_unique<SendMacroList>(1)},                             // EnterWorld.java:353
            {"ItemList", std::make_unique<ItemList>(player, false)},                           // EnterWorld.java:356
            {"ShortcutInit", std::make_unique<ShortcutInit>(player)},                          // EnterWorld.java:359
            {"HennaInfo", std::make_unique<HennaInfo>(player)},                                // EnterWorld.java:362
            {"QuestList", std::make_unique<QuestList>(player)},                                // EnterWorld.java:392
            {"EtcStatusUpdate", std::make_unique<EtcStatusUpdate>(player)},                    // EnterWorld.java:408
            {"ExStorageMaxCount", std::make_unique<ExStorageMaxCount>(player)},                // EnterWorld.java:411
            {"FriendList", std::make_unique<FriendList>(player)},                              // EnterWorld.java:412
            {"SystemMessage(Welcome)", std::make_unique<SystemMessage>(SM_WELCOME_TO_LINEAGE_II)}, // EnterWorld.java:424
            {"SkillList", std::make_unique<SkillList>(player)},                                // EnterWorld.java:464
            {"SkillCoolTime", std::make_unique<SkillCoolTime>(player)},                        // EnterWorld.java:466
            {"UserInfo(broadcast)", std::make_unique<UserInfo>(player)},                       // EnterWorld.java:559
            {"ValidateLocation", std::make_unique<ValidateLocation>(player)},                  // EnterWorld.java:562
            {"ActionFailed", std::make_unique<ActionFailed>()},                                // EnterWorld.java:565
        }};

        for (auto &entry : spawn_sequence)
        {
            log_connection_event(std::string("Sending ") + entry.name);
            send_packet(std::move(entry.packet));
        }

        log_connection_event("*** ENTER WORLD SEQUENCE COMPLETE - ActionFailed sent, client should leave loading screen ***");

    }
    catch (const std::exception &e)
    {
        log_connection_event("Error processing EnterWorld packet: " + std::string(e.what()));
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
// New Packet Handlers
// =============================================================================

void GameClientConnection::handle_request_skill_cool_time_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        log_connection_event("*** RequestSkillCoolTime packet received - CLIENT REQUESTING COOLDOWN INFO ***");

        // Get character info from database
        auto *db_manager = getCharacterDatabaseManager();
        if (!db_manager)
        {
            log_connection_event("ERROR: No database manager available for skill cooldown request");
            return;
        }

        auto character_info = db_manager->getCharacterBySlot(player_name_, character_id_);
        if (!character_info)
        {
            log_connection_event("ERROR: No character info available for skill cooldown request");
            return;
        }

        // Send SkillCoolTime response with current cooldown information
        auto skill_cool_time_response = std::make_unique<SkillCoolTime>(*character_info);
        send_packet(std::move(skill_cool_time_response));
        log_connection_event("*** SkillCoolTime response sent - CLIENT SHOULD RECEIVE COOLDOWN DATA ***");

        // CRITICAL: Send AbnormalStatusUpdate and SkillList after first RequestSkillCoolTime
        // This matches the L2J Mobius sequence exactly
        static bool first_skill_cooltime_request = true;
        if (first_skill_cooltime_request) {
            first_skill_cooltime_request = false;
            
            // Send AbnormalStatusUpdate (status effects)
            auto abnormal_status_response = std::make_unique<AbnormalStatusUpdate>(*character_info);
            send_packet(std::move(abnormal_status_response));
            log_connection_event("*** AbnormalStatusUpdate sent - CRITICAL FOR LOADING SCREEN ***");
            
            // Send SkillList (full skill list)
            auto skill_list_response = std::make_unique<SkillList>(*character_info);
            send_packet(std::move(skill_list_response));
            log_connection_event("*** SkillList sent - FINAL PACKET FOR LOADING SCREEN ***");
        }
    }
    catch (const std::exception &e)
    {
        log_connection_event("ERROR handling RequestSkillCoolTime packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_request_answer_join_pledge_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        // Cast to RequestAnswerJoinPledge to access pledge data
        auto *pledge_packet = dynamic_cast<const RequestAnswerJoinPledge *>(packet.get());
        if (!pledge_packet)
        {
            log_connection_event("Failed to cast packet to RequestAnswerJoinPledge");
            return;
        }

        uint32_t response = pledge_packet->getResponse();
        
        log_connection_event("RequestAnswerJoinPledge received - Response: " + std::string(response == 1 ? "Accept" : "Decline"));

        // TODO: Process pledge join response (matches L2J Mobius implementation)
        // In a real implementation, this would:
        // 1. Get the requestor from player's request partner
        // 2. If response == 0: Send decline messages to both players
        // 3. If response == 1: 
        //    - Add player to clan
        //    - Set pledge type and power grade
        //    - Send JoinPledge, PledgeShowMemberListAdd, PledgeShowInfoUpdate packets
        //    - Broadcast clan updates
        // 4. Clear the request
        
        // For now, send a simple response to acknowledge the packet was received
        // This prevents the client from getting stuck waiting for a response
        if (response == 1)
        {
            // Send a system message indicating the pledge join was accepted
            auto system_message = std::make_unique<SystemMessage>("Pledge join request accepted (stub)");
            send_packet(std::move(system_message));
        }
        else
        {
            // Send a system message indicating the pledge join was declined
            auto system_message = std::make_unique<SystemMessage>("Pledge join request declined (stub)");
            send_packet(std::move(system_message));
        }
        
        log_connection_event("Pledge join response processed (stub implementation)");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error handling RequestAnswerJoinPledge packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_request_item_list_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        log_connection_event("RequestItemList packet received - client wants inventory refresh");

        // Get character info from database
        auto *db_manager = getCharacterDatabaseManager();
        if (!db_manager)
        {
            log_connection_event("No database manager available for inventory request");
            return;
        }

        auto character_info = db_manager->getCharacterBySlot(player_name_, character_id_);
        if (!character_info)
        {
            log_connection_event("No character info available for inventory request");
            return;
        }

        // Send ItemList response with current inventory (showWindow=true to test if it prevents crash)
        auto item_list_response = std::make_unique<ItemList>(*character_info, true);
        send_packet(std::move(item_list_response));
        log_connection_event("ItemList response sent - inventory refreshed (testing showWindow=true)");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error handling RequestItemList packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_request_manor_list_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        log_connection_event("RequestManorList packet received");

        // Send ExSendManorList response (matches L2J Mobius implementation)
        auto manor_list_response = std::make_unique<ExSendManorList>();
        send_packet(std::move(manor_list_response));
        log_connection_event("ExSendManorList response sent");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error handling RequestManorList packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_request_show_mini_map_packet(const std::unique_ptr<ReadablePacket> &packet)
{
    try
    {
        log_connection_event("RequestShowMiniMap packet received (0xCD) - client requesting minimap display");

        // Send ShowMiniMap response (matches L2J Mobius implementation)
        // player.sendPacket(new ShowMiniMap(1665));
        auto show_mini_map_response = std::make_unique<ShowMiniMap>(1665);
        send_packet(std::move(show_mini_map_response));
        log_connection_event("ShowMiniMap response sent with map ID 1665");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error handling RequestShowMiniMap packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_move_backward_to_location_packet(
    const std::unique_ptr<ReadablePacket>& packet)
{
    log_connection_event("Processing MoveBackwardToLocation");

    if (get_game_state() != GameState::IN_GAME) {
        log_connection_event("MoveBackwardToLocation in wrong state - dropping");
        send_packet(std::make_unique<ActionFailed>());
        return;
    }

    auto *move = dynamic_cast<MoveBackwardToLocationPacket*>(packet.get());
    if (!move) {
        log_connection_event("MoveBackwardToLocation cast failed");
        send_packet(std::make_unique<ActionFailed>());
        return;
    }

    auto *db = getCharacterDatabaseManager();
    if (!db) {
        log_connection_event("MoveBackwardToLocation: no db manager");
        send_packet(std::make_unique<ActionFailed>());
        return;
    }
    auto info = db->getCharacterById(character_id_);
    if (!info) {
        log_connection_event("MoveBackwardToLocation: no character " + std::to_string(character_id_));
        send_packet(std::make_unique<ActionFailed>());
        return;
    }
    Player *player = *info;

    const int32_t tx = move->getTargetX();
    const int32_t ty = move->getTargetY();
    const int32_t tz = move->getTargetZ();
    const int32_t ox = move->getOriginX();
    const int32_t oy = move->getOriginY();
    const int32_t oz = move->getOriginZ();

    // Cancel move: origin == target.
    if (tx == ox && ty == oy && tz == oz) {
        player->stopMove();
        send_packet(std::make_unique<ActionFailed>());
        log_connection_event("MoveBackwardToLocation: cancel (origin == target)");
        return;
    }

    // Anti-exploit: huge distance. 9900*9900 = 98010000. Matches Mobius.
    const int64_t dx = static_cast<int64_t>(tx) - static_cast<int64_t>(player->getX());
    const int64_t dy = static_cast<int64_t>(ty) - static_cast<int64_t>(player->getY());
    if ((dx*dx + dy*dy) > 98010000LL) {
        log_connection_event("MoveBackwardToLocation: distance too large - dropping");
        send_packet(std::make_unique<ActionFailed>());
        return;
    }

    const int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    player->setMoveDestination(tx, ty, tz, nowMs);

    send_packet(std::make_unique<MoveToLocation>(player));
    log_connection_event("MoveBackwardToLocation: dest set to ("
        + std::to_string(tx) + "," + std::to_string(ty) + "," + std::to_string(tz) + ")");
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

void GameClientConnection::handle_validate_position_packet(
    const std::unique_ptr<ReadablePacket>& packet)
{
    if (get_game_state() != GameState::IN_GAME) {
        return; // silent - these packets are noisy
    }

    auto *vp = dynamic_cast<ValidatePositionPacket*>(packet.get());
    if (!vp) return;

    auto *db = getCharacterDatabaseManager();
    if (!db) return;
    auto info = db->getCharacterById(character_id_);
    if (!info) return;
    Player *player = *info;

    const int32_t cx = vp->getX();
    const int32_t cy = vp->getY();
    const int32_t cz = vp->getZ();
    const int32_t ch = vp->getHeading();

    const int64_t dx = static_cast<int64_t>(cx) - static_cast<int64_t>(player->getX());
    const int64_t dy = static_cast<int64_t>(cy) - static_cast<int64_t>(player->getY());
    const int64_t delta2 = dx*dx + dy*dy;

    // Mobius threshold: 360000 = 600*600. Above this we don't trust the client.
    if (delta2 < 360000LL) {
        player->setPosition(cx, cy, cz);
        player->setHeading(ch);
    } else {
        // Snap client back to server-authoritative pos.
        send_packet(std::make_unique<ValidateLocation>(player));
        log_connection_event("ValidatePosition delta too large - sent ValidateLocation");
    }

    // Always update client-mirror.
    player->setClientPosition(cx, cy, cz);
    player->setClientHeading(ch);
}
