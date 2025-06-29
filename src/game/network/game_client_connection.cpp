#include "game_client_connection.hpp"
#include "game_connection_manager.hpp"
#include "../packets/packet_factory.hpp"
#include "../packets/responses/ping_response.hpp"
#include "../packets/requests/no_op_packet.hpp"
#include "../packets/requests/protocol_version_packet.hpp"
#include "../packets/requests/auth_login_packet.hpp"
#include "../packets/responses/version_check_response.hpp"
#include "../packets/responses/character_selection_info.hpp"

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

        // Debug logging
        std::string hex_dump = "Raw packet data: ";
        for (size_t i = 0; i < std::min(packet_data.size(), size_t(16)); ++i)
        {
            char hex_byte[4];
            snprintf(hex_byte, sizeof(hex_byte), "%02X ", packet_data[i]);
            hex_dump += hex_byte;
        }
        if (packet_data.size() > 16)
            hex_dump += "...";
        log_connection_event(hex_dump);

        // Decrypt the packet
        if (!decrypt_incoming_packet(packet_data))
        {
            log_connection_event("Failed to decrypt incoming packet");
            force_disconnect();
            return;
        }

        // After successful decryption, refresh opcode
        actual_opcode = packet_data[0];

        // Debug logging after decryption
        hex_dump = "After decryption: ";
        for (size_t i = 0; i < std::min(packet_data.size(), size_t(16)); ++i)
        {
            char hex_byte[4];
            snprintf(hex_byte, sizeof(hex_byte), "%02X ", packet_data[i]);
            hex_dump += hex_byte;
        }
        if (packet_data.size() > 16)
            hex_dump += "...";
        log_connection_event(hex_dump);

        // Use GamePacketFactory to create and handle packets
        try
        {
            auto packet = GamePacketFactory::createFromClientData(packet_data);
            if (packet)
            {
                handle_game_packet(std::move(packet), actual_opcode);
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
            log_connection_event("Using XOR decryption for incoming packet");
            return game_encryption_->decrypt(packet_data);
        }
        else if (blowfish_encryption_)
        {
            log_connection_event("Using BLOWFISH decryption for incoming packet");
            return blowfish_encryption_->decrypt(packet_data);
        }
        // If no encryption is set up yet, packets are in plaintext
        log_connection_event("Decrypting packet in plaintext mode (encryption not initialized)");
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
            game_encryption_->encrypt(packet_data);
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

void GameClientConnection::handle_game_packet(std::unique_ptr<ReadablePacket> packet, uint8_t actual_opcode)
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
        case 0x0B: // RequestCharacterCreate
            log_connection_event("RequestCharacterCreate packet received");
            break;
        case 0x0C: // RequestCharacterDelete
            log_connection_event("RequestCharacterDelete packet received");
            break;
        case 0x0D: // RequestGameStart (character selection)
            log_connection_event("RequestGameStart packet received");
            break;
        case 0x0E: // RequestNewCharacter
            log_connection_event("RequestNewCharacter packet received");
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

void GameClientConnection::handle_no_op_packet(const std::unique_ptr<ReadablePacket>& packet)
{
    try
    {
        // Cast to NoOpPacket to access ping data
        auto* ping_packet = dynamic_cast<const NoOpPacket*>(packet.get());
        if (!ping_packet)
        {
            log_connection_event("Failed to cast packet to NoOpPacket");
            return;
        }

        const auto& ping_data = ping_packet->getPingData();
        
        // Log the ping request with data size
        log_connection_event("Ping packet received with " + std::to_string(ping_data.size()) + " bytes of data");
        
        // Create and send ping response (echo back the same data)
        auto ping_response = std::make_unique<PingResponse>(ping_data);
        send_packet(std::move(ping_response));
        
        log_connection_event("Ping response sent successfully");
    }
    catch (const std::exception& e)
    {
        log_connection_event("Error handling ping packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_protocol_version_packet(const std::unique_ptr<ReadablePacket>& packet)
{
    try
    {
        // Cast to ProtocolVersionPacket to access version data
        auto* protocol_packet = dynamic_cast<const ProtocolVersionPacket*>(packet.get());
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
                0x45, 0xa3, 0x7a, 0x86, 0xf0, 0x33, 0x40, 0x64
            };
            
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

            if (blowfish_encryption_) {
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
    catch (const std::exception& e)
    {
        log_connection_event("Error handling protocol version packet: " + std::string(e.what()));
    }
}

void GameClientConnection::handle_request_login_packet(const std::unique_ptr<ReadablePacket>& packet)
{
    try
    {
        // Cast to AuthLoginPacket to access session data
        auto* login_packet = dynamic_cast<const AuthLoginPacket*>(packet.get());
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

        // Send CharacterSelectionInfo with empty character list
        auto char_select_packet = CharacterSelectionInfo::createWithTestCharacter(username);

        log_connection_event("Sending CharacterSelectionInfo (empty list)");

        send_packet(std::move(char_select_packet));

        log_connection_event("Game server authentication successful - CharacterSelectionInfo sent");
    }
    catch (const std::exception& e)
    {
        log_connection_event("Error handling RequestLogin packet: " + std::string(e.what()));
        // TODO: Send login failure response
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

void GameClientConnection::initialize_encryption(const std::vector<uint8_t> &key)
{
    try
    {
        game_encryption_ = std::make_unique<GameClientEncryption>(key);
        game_encryption_->enable(); // ensure first encrypted packet is handled correctly

        // Optional fallback: clear Blowfish (our current client uses XOR)
        blowfish_encryption_.reset();

        log_connection_event("Game client XOR encryption ENABLED");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Failed to initialize encryption: " + std::string(e.what()));
    }
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