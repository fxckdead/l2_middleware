# Core Rust Files to Review Per Phase

## Phase 1: Packet Factory Extension
Primary Files:
```
// Compare these packet factories - see the complexity difference
game/src/cp_factory.rs           // Game Server: 20+ packet types
login/src/packet/cp_factory.rs   // Login Server: 4 packet types
```
Key Focus Points:
Game Server (cp_factory.rs): Notice the PlayerPackets enum with 14+ variants
Login Server (cp_factory.rs): Simple ClientPackets enum with 4 variants
Extended Packets: See how game server handles 0xD0 extended packets with sub-opcodes
Supporting Files:
```
game/src/packets/from_client/mod.rs     // All game packet types
login/src/packet/from_client/mod.rs     // Simple login packet types
```

## Phase 2: Game Controller & State Management
Primary Files:
```
// The complexity explosion happens here
game/src/controller.rs                   // Game Controller (114 lines)
login/src/controller/data.rs            // Login Controller (82 lines)
```
Key Focus Points:
Game Controller: Complex state with exp_table, action_list, class_templates, clan_ally_manager
Login Controller: Simple state with just key_pairs, game_servers, players
Character Template System:
```
game/src/data/char_template.rs          // 305 lines - VERY COMPLEX
game/src/data/base_stat.rs              // Base statistics system
game/src/data/exp_table.rs              // Experience progression
game/src/data/action_list.rs            // Available actions
```
Supporting Files:
```
game/src/data/classes/mapping.rs        // Class type definitions
l2-core/src/config/gs.rs               // Game server configuration
l2-core/src/config/login.rs            // Login server configuration (compare)
```
## Phase 3: Key Packet Handlers
Simple Packet Handlers (Start Here):
```
game/src/packets/from_client/protocol.rs        // Protocol version
game/src/packets/from_client/auth.rs           // Authentication (253 lines)
game/src/packets/from_client/char_create.rs    // Character creation (266 lines)
game/src/packets/from_client/char_select.rs    // Character selection (180 lines)
```
Complex Packet Handler (The Big One):
```
game/src/packets/from_client/enter_world.rs    // 195 lines - MOST COMPLEX
// ⚠️ This file shows 50+ TODO operations - study this carefully!
```
Compare with Login Server Handlers:
```
login/src/packet/from_client/req_auth_login.rs     // Simple auth (254 lines)
login/src/packet/from_client/req_server_list.rs    // Simple server list (133 lines)
```
Response Packets:
```
game/src/packets/to_client/user_info.rs        // Player information
game/src/packets/to_client/char_selection.rs   // Character list
game/src/packets/to_client/item_list.rs        // Inventory
```
# Phase 4: Dual Network Architecture
Primary Files:
```
// Main entry points - see the dual listener pattern
game/src/main.rs                        // Game Server main (105 lines)
login/src/main.rs                       // Login Server main (102 lines)
```
Key Focus Points in game/src/main.rs:
Line 48-58: Player listener setup
Line 70-82: Login Server connector setup
Line 89-105: Dual tokio::select! event loop
Connection Management:
```
game/src/pl_client.rs                   // Player client connection (330 lines)
game/src/ls_client.rs                   // Login server client (145 lines)
login/src/login_client.rs               // Login client (193 lines)
login/src/gs_client.rs                  // Game server client (145 lines)
```
Network Layer:
```
l2-core/src/network/connection.rs       // Base connection actor (319 lines)
l2-core/src/network/listener.rs         // Connection listener (98 lines)
l2-core/src/network/connector.rs        // Outbound connector (67 lines)
```
Inter-Server Communication
Game Server to Login Server:
```
l2-core/src/shared_packets/gs_2_ls/     // Game → Login packets
├── player_auth_request.rs              // Authentication requests
├── player_in_game.rs                   // Player status updates
├── player_logout.rs                    // Logout notifications
└── player_tracert.rs                   // Network diagnostics
```
Login Server to Game Server:
```
l2-core/src/shared_packets/ls_2_gs/     // Login → Game packets
├── auth_gs.rs                          // Game server authentication
├── init_ls.rs                          // Connection initialization
├── player_auth_response.rs             // Auth responses
└── kick_player.rs                      // Player kicks
```
## Critical Files for Understanding Complexity
🔥 MUST READ - High Impact:
```
game/src/packets/from_client/enter_world.rs - Shows the 50+ operations complexity
game/src/controller.rs vs login/src/controller/data.rs - Complexity comparison
game/src/data/char_template.rs - Character system complexity
game/src/main.rs vs login/src/main.rs - Dual vs single listener pattern
```
📚 Supporting Context:
```
game/src/cp_factory.rs vs login/src/packet/cp_factory.rs - Packet complexity
l2-core/src/network/connection.rs - Base connection patterns
l2-core/src/shared_packets/ - Inter-server communication
```