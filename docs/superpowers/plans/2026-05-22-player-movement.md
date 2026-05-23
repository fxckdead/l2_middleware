# Player Movement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the player visibly walk to a clicked location, with the server authoritative on position. Server reads `MoveBackwardToLocation` (0x01), simulates per-tick movement on a `boost::asio::steady_timer` owned by `GameServer`, and reconciles via `ValidatePosition` (0x48).

**Architecture:** Two cooperating layers, both additive. **Packet/state layer** — three new request packets, one fix to an existing response, and new fields/methods on `Player`. **World-tick layer** — a single `steady_timer` on `GameServer`'s existing `io_context_` that iterates connected players and advances anyone moving. The two layers do not depend on each other to compile.

**Tech Stack:** C++20, Boost.Asio, CMake/Ninja, vcpkg. Reference port from L2J Mobius Interlude (Java) at `C:\Users\chris\Code\L2J_Mobius\L2J_Mobius_CT_0_Interlude\`. Per `CLAUDE.md`, **do not write automated tests** — verification is build + manual smoke.

**Spec:** [docs/superpowers/specs/2026-05-22-player-movement-design.md](../specs/2026-05-22-player-movement-design.md)

---

## File map

**New files (4):**
- `src/game/packets/requests/move_backward_to_location_packet.hpp`
- `src/game/packets/requests/move_backward_to_location_packet.cpp`
- `src/game/packets/requests/validate_position_packet.hpp`
- `src/game/packets/requests/validate_position_packet.cpp`

**Modified files (9):**
- `src/game/entities/player.hpp` — destination + movement state, getters, `setMoveDestination`, `stopMove`, `advanceMovement`, client-mirror setters
- `src/game/entities/player.cpp` — field init in constructor, method bodies
- `src/game/packets/responses/move_to_location.cpp` — replace 3 `TODO` placeholders with real destination accessors
- `src/game/packets/packet_factory.hpp` — add `ValidatePosition = 0x48` enum value + create-helper decls
- `src/game/packets/packet_factory.cpp` — replace `MoveBackwardToLocation` NoOp routing, add `ValidatePosition` case
- `src/game/network/game_client_connection.hpp` — declare 2 new handlers + `advance_player_movement` + access to `CharacterDatabaseManager` helper (already exists)
- `src/game/network/game_client_connection.cpp` — implement handlers, wire into opcode switch
- `src/game/server/game_server.hpp` — `world_tick_timer_` member + `start_world_tick`/`process_world_tick` decls + interval constant
- `src/game/server/game_server.cpp` — timer construction in `initialize_server`, tick body, cancel in `shutdown_server`
- `CMakeLists.txt` — add the 4 new `.cpp` sources to `L2GameServer`

---

## Reference: existing patterns to follow

- Packet-id convention: client opcodes are listed in `enum class GameClientPacketType` in `packet_factory.hpp`; the factory's `createFromClientData` switch builds one per opcode; the connection's `handle_game_packet` switch dispatches to a `handle_*_packet` method.
- Naming: `PascalCase` types, `camelCase` methods/vars, `SCREAMING_SNAKE_CASE` constants, `_member` or `m_member` for fields. Existing `Player` uses `trailingUnderscore_` field convention — match that.
- `SendablePacketBuffer` writes use *capital* `writeUInt8/writeUInt32/writeInt32`. `ReadablePacketBuffer` uses `readByte()` for `uint8_t`, `readInt32()` for `int32_t`. Opcode is consumed by the factory before reaching `read()`.
- Player retrieval inside a handler (existing pattern from `handle_enter_world_packet`):
  ```cpp
  auto *db = getCharacterDatabaseManager();
  if (!db) { /* log + return */ }
  auto info = db->getCharacterBySlot(player_name_, character_id_);
  if (!info) { /* log + return */ }
  Player *player = *info;   // raw, owned by db_manager
  ```
- Send to self: `send_packet(std::make_unique<PacketType>(args...))`.
- Opcode verification: server `PACKET_ID` constants must match `L2J_Mobius\...\gameserver\network\ServerPackets.java`; client opcodes must match `ClientPackets.java`.

---

## Task 1: Extend `Player` with destination + movement state

**Files:**
- Modify: `src/game/entities/player.hpp` (add fields, getters, method decls)
- Modify: `src/game/entities/player.cpp` (initialize fields, define methods)

This is the foundation — every later task assumes these accessors exist.

- [ ] **Step 1: Add member fields in `player.hpp`**

  Find the existing block of `uint32_t` stubbed properties starting around `class Player` private section (after `paperdollItemIds_`). Add this block right before the `std::vector<uint32_t> skills_;` line:

  ```cpp
  // --- Movement (Player Movement plan: 2026-05-22) ---
  // Authoritative destination set by MoveBackwardToLocation; consumed by world tick.
  int32_t xDst_ = 0;
  int32_t yDst_ = 0;
  int32_t zDst_ = 0;
  bool isMoving_ = false;
  int64_t lastMoveTickMs_ = 0;

  // Mirror of what the client thinks. Updated by ValidatePosition.
  // Stored now so future code (combat, casting) can ask cheaply.
  int32_t clientX_ = 0;
  int32_t clientY_ = 0;
  int32_t clientZ_ = 0;
  int32_t clientHeading_ = 0;
  ```

- [ ] **Step 2: Add public method declarations in `player.hpp`**

  Inside the public section, near `setPaperdollItemId(...)` and before `void dump() const;`:

  ```cpp
  // --- Movement (Player Movement plan: 2026-05-22) ---
  int32_t getDestX() const { return xDst_; }
  int32_t getDestY() const { return yDst_; }
  int32_t getDestZ() const { return zDst_; }
  bool isMoving() const { return isMoving_; }
  int64_t getLastMoveTickMs() const { return lastMoveTickMs_; }

  int32_t getClientX() const { return clientX_; }
  int32_t getClientY() const { return clientY_; }
  int32_t getClientZ() const { return clientZ_; }
  int32_t getClientHeading() const { return clientHeading_; }

  void setClientPosition(int32_t x, int32_t y, int32_t z);
  void setClientHeading(int32_t heading);

  // Begin moving toward (x,y,z). Recomputes heading from current position.
  void setMoveDestination(int32_t x, int32_t y, int32_t z, int64_t nowMs);

  // Clear isMoving_; leaves x_,y_,z_ where they are.
  void stopMove();

  // Advance x_,y_,z_ toward dest using runSpeed * dt. Snaps + stops within 16 units.
  void advanceMovement(int64_t nowMs);
  ```

- [ ] **Step 3: Initialize fields in `player.cpp` constructor**

  In `Player::Player(...)`'s member-initializer list (after `, paperdollItemIds_(16, 0)`), insert these initializers. They have in-class default initializers in the header, but listing them explicitly here matches the existing style and documents the constructor contract:

  ```cpp
      , xDst_(0)
      , yDst_(0)
      , zDst_(0)
      , isMoving_(false)
      , lastMoveTickMs_(0)
      , clientX_(0)
      , clientY_(0)
      , clientZ_(0)
      , clientHeading_(0)
  ```

- [ ] **Step 4: Add method bodies at the end of `player.cpp`**

  Append to `player.cpp`. Add `#include <cmath>` and `#include <algorithm>` near the top of the file if not already present.

  ```cpp
  void Player::setClientPosition(int32_t x, int32_t y, int32_t z)
  {
      clientX_ = x;
      clientY_ = y;
      clientZ_ = z;
  }

  void Player::setClientHeading(int32_t heading)
  {
      clientHeading_ = heading;
  }

  void Player::setMoveDestination(int32_t x, int32_t y, int32_t z, int64_t nowMs)
  {
      xDst_ = x;
      yDst_ = y;
      zDst_ = z;

      // L2 heading: 16-bit (0..65535) covering one full turn, atan2(dy, dx) * 32768/pi.
      const double dx = static_cast<double>(x) - static_cast<double>(getX());
      const double dy = static_cast<double>(y) - static_cast<double>(getY());
      const double radians = std::atan2(dy, dx);
      const double pi = 3.14159265358979323846;
      int32_t heading = static_cast<int32_t>(radians * 32768.0 / pi);
      // Normalize into [0, 65535].
      heading &= 0xFFFF;
      setHeading(heading);

      isMoving_ = true;
      lastMoveTickMs_ = nowMs;
  }

  void Player::stopMove()
  {
      isMoving_ = false;
  }

  void Player::advanceMovement(int64_t nowMs)
  {
      if (!isMoving_) {
          return;
      }

      // Clamp dt to [0, 1000] ms: guards first tick (lastMoveTickMs_ may equal nowMs)
      // and pathological pauses (e.g. server stalls).
      int64_t dt = nowMs - lastMoveTickMs_;
      if (dt < 0) dt = 0;
      if (dt > 1000) dt = 1000;
      lastMoveTickMs_ = nowMs;

      const double dx = static_cast<double>(xDst_) - static_cast<double>(getX());
      const double dy = static_cast<double>(yDst_) - static_cast<double>(getY());
      const double dz = static_cast<double>(zDst_) - static_cast<double>(getZ());
      const double dist = std::sqrt(dx*dx + dy*dy + dz*dz);

      // Arrival epsilon = 16 (matches Mobius geodata cell size).
      if (dist < 16.0) {
          setPosition(xDst_, yDst_, zDst_);
          isMoving_ = false;
          return;
      }

      const double step = (static_cast<double>(getRunSpeed()) * static_cast<double>(dt)) / 1000.0;
      if (step >= dist) {
          // Would overshoot - snap.
          setPosition(xDst_, yDst_, zDst_);
          isMoving_ = false;
          return;
      }

      const double frac = step / dist;
      const int32_t nx = static_cast<int32_t>(static_cast<double>(getX()) + dx * frac);
      const int32_t ny = static_cast<int32_t>(static_cast<double>(getY()) + dy * frac);
      const int32_t nz = static_cast<int32_t>(static_cast<double>(getZ()) + dz * frac);
      setPosition(nx, ny, nz);
  }
  ```

- [ ] **Step 5: Build**

  Run: `cmake --build --preset game-debug`
  Expected: success, no new warnings. `L2GameServer` builds.

- [ ] **Step 6: Commit**

  ```bash
  git add src/game/entities/player.hpp src/game/entities/player.cpp
  git commit -m "feat(player): add destination + movement state and advanceMovement"
  ```

---

## Task 2: Fix `MoveToLocation` to use real destination

**Files:**
- Modify: `src/game/packets/responses/move_to_location.cpp:5-18`

The packet exists but its constructor sets `xDst/yDst/zDst` to the player's *current* position (TODO comments). Task 1 added real accessors; wire them in.

- [ ] **Step 1: Edit `move_to_location.cpp` constructor**

  Replace lines 5–18 (`MoveToLocation::MoveToLocation(...)`) with:

  ```cpp
  MoveToLocation::MoveToLocation(const Player* player)
      : m_objectId(0),
        m_x(0), m_y(0), m_z(0),
        m_xDst(0), m_yDst(0), m_zDst(0)
  {
      if (!player)
      {
          throw std::invalid_argument("Player cannot be null for MoveToLocation packet");
      }
      m_objectId = player->getObjectId();
      m_x = player->getX();
      m_y = player->getY();
      m_z = player->getZ();
      m_xDst = player->getDestX();
      m_yDst = player->getDestY();
      m_zDst = player->getDestZ();
  }
  ```

  Rationale: order moved so the null-check runs before dereferencing `player`. Same fields, same wire layout — only the source values change.

- [ ] **Step 2: Build**

  Run: `cmake --build --preset game-debug`
  Expected: success.

- [ ] **Step 3: Commit**

  ```bash
  git add src/game/packets/responses/move_to_location.cpp
  git commit -m "fix(move_to_location): use real destination from Player"
  ```

---

## Task 3: Create `MoveBackwardToLocationPacket` request class

**Files:**
- Create: `src/game/packets/requests/move_backward_to_location_packet.hpp`
- Create: `src/game/packets/requests/move_backward_to_location_packet.cpp`
- Modify: `CMakeLists.txt` (add `.cpp` to `L2GameServer` source list)

Reads 7 × int32 per Mobius `MoveBackwardToLocation.java:46-55`.

- [ ] **Step 1: Write the header**

  Create `src/game/packets/requests/move_backward_to_location_packet.hpp`:

  ```cpp
  #pragma once

  #include "../../../core/packets/packet.hpp"
  #include "../../../core/network/packet_buffer.hpp"
  #include <cstdint>

  // Client -> server packet (opcode 0x01).
  // Mobius reference: gameserver/network/clientpackets/MoveBackwardToLocation.java
  // Wire layout: 7 x int32 = targetX, targetY, targetZ, originX, originY, originZ, movementMode
  // movementMode == 0 if cursor keys are used, 1 if mouse is used.
  class MoveBackwardToLocationPacket : public ReadablePacket
  {
  private:
      static constexpr uint8_t PACKET_ID = 0x01;

  public:
      MoveBackwardToLocationPacket() = default;

      uint8_t getPacketId() const override { return PACKET_ID; }
      std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
      void read(ReadablePacketBuffer &buffer) override;

      int32_t getTargetX() const { return m_targetX; }
      int32_t getTargetY() const { return m_targetY; }
      int32_t getTargetZ() const { return m_targetZ; }
      int32_t getOriginX() const { return m_originX; }
      int32_t getOriginY() const { return m_originY; }
      int32_t getOriginZ() const { return m_originZ; }
      int32_t getMovementMode() const { return m_movementMode; }

  private:
      int32_t m_targetX = 0;
      int32_t m_targetY = 0;
      int32_t m_targetZ = 0;
      int32_t m_originX = 0;
      int32_t m_originY = 0;
      int32_t m_originZ = 0;
      int32_t m_movementMode = 0;
  };
  ```

- [ ] **Step 2: Write the implementation**

  Create `src/game/packets/requests/move_backward_to_location_packet.cpp`:

  ```cpp
  #include "move_backward_to_location_packet.hpp"

  void MoveBackwardToLocationPacket::read(ReadablePacketBuffer &buffer)
  {
      m_targetX = buffer.readInt32();
      m_targetY = buffer.readInt32();
      m_targetZ = buffer.readInt32();
      m_originX = buffer.readInt32();
      m_originY = buffer.readInt32();
      m_originZ = buffer.readInt32();
      m_movementMode = buffer.readInt32();
  }
  ```

- [ ] **Step 3: Add to `CMakeLists.txt`**

  In the `add_executable(L2GameServer ...)` block, find the comment `# Game request packets` and the line `src/game/packets/requests/request_show_mini_map.cpp`. Insert this line right after it:

  ```cmake
      src/game/packets/requests/move_backward_to_location_packet.cpp
  ```

- [ ] **Step 4: Build**

  Run: `cmake --build --preset game-debug`
  Expected: success. The new packet compiles even though nothing references it yet (Task 5 will).

- [ ] **Step 5: Commit**

  ```bash
  git add src/game/packets/requests/move_backward_to_location_packet.hpp \
          src/game/packets/requests/move_backward_to_location_packet.cpp \
          CMakeLists.txt
  git commit -m "feat(packets): add MoveBackwardToLocationPacket request (opcode 0x01)"
  ```

---

## Task 4: Create `ValidatePositionPacket` request class

**Files:**
- Create: `src/game/packets/requests/validate_position_packet.hpp`
- Create: `src/game/packets/requests/validate_position_packet.cpp`
- Modify: `CMakeLists.txt`

Reads 5 × int32 per Mobius `ValidatePosition.java:37-45`. We discard `vehicleId` (no vehicles in scope).

- [ ] **Step 1: Write the header**

  Create `src/game/packets/requests/validate_position_packet.hpp`:

  ```cpp
  #pragma once

  #include "../../../core/packets/packet.hpp"
  #include "../../../core/network/packet_buffer.hpp"
  #include <cstdint>

  // Client -> server packet (opcode 0x48).
  // Mobius reference: gameserver/network/clientpackets/ValidatePosition.java
  // Wire layout: 5 x int32 = x, y, z, heading, vehicleId
  // vehicleId is read but ignored (no vehicles in scope).
  class ValidatePositionPacket : public ReadablePacket
  {
  private:
      static constexpr uint8_t PACKET_ID = 0x48;

  public:
      ValidatePositionPacket() = default;

      uint8_t getPacketId() const override { return PACKET_ID; }
      std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
      void read(ReadablePacketBuffer &buffer) override;

      int32_t getX() const { return m_x; }
      int32_t getY() const { return m_y; }
      int32_t getZ() const { return m_z; }
      int32_t getHeading() const { return m_heading; }

  private:
      int32_t m_x = 0;
      int32_t m_y = 0;
      int32_t m_z = 0;
      int32_t m_heading = 0;
      int32_t m_vehicleId = 0; // read + discarded
  };
  ```

- [ ] **Step 2: Write the implementation**

  Create `src/game/packets/requests/validate_position_packet.cpp`:

  ```cpp
  #include "validate_position_packet.hpp"

  void ValidatePositionPacket::read(ReadablePacketBuffer &buffer)
  {
      m_x = buffer.readInt32();
      m_y = buffer.readInt32();
      m_z = buffer.readInt32();
      m_heading = buffer.readInt32();
      m_vehicleId = buffer.readInt32(); // discarded
  }
  ```

- [ ] **Step 3: Add to `CMakeLists.txt`**

  Right after the `move_backward_to_location_packet.cpp` line added in Task 3, insert:

  ```cmake
      src/game/packets/requests/validate_position_packet.cpp
  ```

- [ ] **Step 4: Build**

  Run: `cmake --build --preset game-debug`
  Expected: success.

- [ ] **Step 5: Commit**

  ```bash
  git add src/game/packets/requests/validate_position_packet.hpp \
          src/game/packets/requests/validate_position_packet.cpp \
          CMakeLists.txt
  git commit -m "feat(packets): add ValidatePositionPacket request (opcode 0x48)"
  ```

---

## Task 5: Wire both opcodes into `PacketFactory`

**Files:**
- Modify: `src/game/packets/packet_factory.hpp`
- Modify: `src/game/packets/packet_factory.cpp`

Replace the `MoveBackwardToLocation` NoOp routing with a real packet, and add a new `ValidatePosition` case.

- [ ] **Step 1: Add `ValidatePosition` to the enum in `packet_factory.hpp`**

  In `enum class GameClientPacketType : uint8_t`, find the line `RequestSkillCoolTime = 0x9D,`. Insert the new value right before it (keeps numeric order):

  ```cpp
      ValidatePosition = 0x48,        // Client position update (Mobius VALIDATE_POSITION)
  ```

- [ ] **Step 2: Add the two new includes and factory-helper declarations in `packet_factory.hpp`**

  Near the top of the file, after `#include "requests/request_show_mini_map.hpp"`, add:

  ```cpp
  #include "requests/move_backward_to_location_packet.hpp"
  #include "requests/validate_position_packet.hpp"
  ```

  In the private section of `class GamePacketFactory`, near the other `static std::unique_ptr<ReadablePacket> createXxxPacket(...)` declarations, add:

  ```cpp
      static std::unique_ptr<ReadablePacket> createMoveBackwardToLocationPacket(const std::vector<uint8_t> &rawData);
      static std::unique_ptr<ReadablePacket> createValidatePositionPacket(const std::vector<uint8_t> &rawData);
  ```

- [ ] **Step 3: Replace `MoveBackwardToLocation` routing in `packet_factory.cpp:40-42`**

  Find:

  ```cpp
      case GameClientPacketType::MoveBackwardToLocation:
          // 0x01 - Movement packet
          return createNoOpPacket(packetData);
  ```

  Replace with:

  ```cpp
      case GameClientPacketType::MoveBackwardToLocation:
          // 0x01 - Movement packet
          return createMoveBackwardToLocationPacket(packetData);
  ```

- [ ] **Step 4: Add `ValidatePosition` case in `packet_factory.cpp`**

  Find the case for `RequestSkillCoolTime` (`case GameClientPacketType::RequestSkillCoolTime:`). Insert this case immediately before it:

  ```cpp
      case GameClientPacketType::ValidatePosition:
          // 0x48 - Client position update for reconciliation
          return createValidatePositionPacket(packetData);
  ```

- [ ] **Step 5: Define the two helpers at the bottom of `packet_factory.cpp`**

  Append (or insert near the other `createXxxPacket` definitions — match existing layout):

  ```cpp
  std::unique_ptr<ReadablePacket> GamePacketFactory::createMoveBackwardToLocationPacket(
      const std::vector<uint8_t> &rawData)
  {
      try
      {
          ReadablePacketBuffer buffer(rawData);
          auto packet = std::make_unique<MoveBackwardToLocationPacket>();
          packet->read(buffer);
          return packet;
      }
      catch (const std::exception &e)
      {
          throw PacketException("Failed to create MoveBackwardToLocation packet: " + std::string(e.what()));
      }
  }

  std::unique_ptr<ReadablePacket> GamePacketFactory::createValidatePositionPacket(
      const std::vector<uint8_t> &rawData)
  {
      try
      {
          ReadablePacketBuffer buffer(rawData);
          auto packet = std::make_unique<ValidatePositionPacket>();
          packet->read(buffer);
          return packet;
      }
      catch (const std::exception &e)
      {
          throw PacketException("Failed to create ValidatePosition packet: " + std::string(e.what()));
      }
  }
  ```

  This pattern (try/catch wrapping `ReadablePacketBuffer buffer(rawData); make_unique<X>(); ->read(buffer);`) matches every existing helper in this file — confirmed by reading `createNoOpPacket`, `createProtocolVersionPacket`, `createAuthLoginPacket`, etc.

- [ ] **Step 6: Build**

  Run: `cmake --build --preset game-debug`
  Expected: success.

- [ ] **Step 7: Commit**

  ```bash
  git add src/game/packets/packet_factory.hpp src/game/packets/packet_factory.cpp
  git commit -m "feat(factory): route MoveBackwardToLocation (0x01) and ValidatePosition (0x48)"
  ```

---

## Task 6: Add `MoveBackwardToLocation` handler to `GameClientConnection`

**Files:**
- Modify: `src/game/network/game_client_connection.hpp` (add handler decl)
- Modify: `src/game/network/game_client_connection.cpp` (define handler, wire opcode switch)

- [ ] **Step 1: Add includes at the top of `game_client_connection.cpp`**

  Near the other packet includes:

  ```cpp
  #include "../packets/requests/move_backward_to_location_packet.hpp"
  #include "../packets/responses/move_to_location.hpp"
  #include "../packets/responses/action_failed.hpp"
  #include "../entities/player.hpp"
  #include "../server/character_database_manager.hpp"
  #include <chrono>
  ```

  Skip any that are already present.

- [ ] **Step 2: Declare handler in `game_client_connection.hpp`**

  In the `private:` section of `class GameClientConnection`, near the other `handle_*_packet` declarations (after `handle_request_show_mini_map_packet`), add:

  ```cpp
      void handle_move_backward_to_location_packet(const std::unique_ptr<ReadablePacket>& packet);
  ```

- [ ] **Step 3: Implement the handler in `game_client_connection.cpp`**

  Append to the bottom of the file (or near other `handle_*` methods — match existing layout):

  ```cpp
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
  ```

- [ ] **Step 4: Wire into `handle_game_packet` opcode switch**

  In `game_client_connection.cpp` find the existing case:

  ```cpp
          case 0x01: // MoveBackwardToLocation
              log_connection_event("MoveBackwardToLocation packet received");
              break;
  ```

  Replace it with:

  ```cpp
          case 0x01: // MoveBackwardToLocation
              handle_move_backward_to_location_packet(packet);
              break;
  ```

- [ ] **Step 5: Build**

  Run: `cmake --build --preset game-debug`
  Expected: success.

- [ ] **Step 6: Commit**

  ```bash
  git add src/game/network/game_client_connection.hpp src/game/network/game_client_connection.cpp
  git commit -m "feat(connection): handle MoveBackwardToLocation - set dest + echo MoveToLocation"
  ```

---

## Task 7: Add `ValidatePosition` handler to `GameClientConnection`

**Files:**
- Modify: `src/game/network/game_client_connection.hpp`
- Modify: `src/game/network/game_client_connection.cpp`

- [ ] **Step 1: Add include at the top of `game_client_connection.cpp`**

  Add (skip if already present from Task 6):

  ```cpp
  #include "../packets/requests/validate_position_packet.hpp"
  #include "../packets/responses/validate_location.hpp"
  ```

- [ ] **Step 2: Declare handler in `game_client_connection.hpp`**

  In the `private:` section, after the `handle_move_backward_to_location_packet` declaration added in Task 6:

  ```cpp
      void handle_validate_position_packet(const std::unique_ptr<ReadablePacket>& packet);
  ```

- [ ] **Step 3: Implement the handler in `game_client_connection.cpp`**

  Append:

  ```cpp
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
  ```

- [ ] **Step 4: Wire into `handle_game_packet` opcode switch**

  In `game_client_connection.cpp`'s `handle_game_packet` switch, find the case for `0x9D` (RequestSkillCoolTime). Insert a new case immediately before it:

  ```cpp
          case 0x48: // ValidatePosition - client position update for reconciliation
              handle_validate_position_packet(packet);
              break;
  ```

- [ ] **Step 5: Build**

  Run: `cmake --build --preset game-debug`
  Expected: success.

- [ ] **Step 6: Commit**

  ```bash
  git add src/game/network/game_client_connection.hpp src/game/network/game_client_connection.cpp
  git commit -m "feat(connection): handle ValidatePosition - reconcile or snap with ValidateLocation"
  ```

---

## Task 8: Expose `advance_player_movement` on `GameClientConnection`

**Files:**
- Modify: `src/game/network/game_client_connection.hpp`
- Modify: `src/game/network/game_client_connection.cpp`

The world tick (Task 9) iterates connections and calls this per connection. Lives on the connection so the connection still owns its own dispatch.

- [ ] **Step 1: Declare in `game_client_connection.hpp`**

  In the `public:` section, near `send_packet`:

  ```cpp
      // Called by GameServer's world tick. Advances the attached player's position
      // toward destination if the player is moving. No-op if not in IN_GAME or no character.
      void advance_player_movement(int64_t nowMs);
  ```

- [ ] **Step 2: Implement in `game_client_connection.cpp`**

  Append:

  ```cpp
  void GameClientConnection::advance_player_movement(int64_t nowMs)
  {
      if (get_game_state() != GameState::IN_GAME) return;
      if (character_id_ == 0) return;

      auto *db = getCharacterDatabaseManager();
      if (!db) return;
      auto info = db->getCharacterById(character_id_);
      if (!info) return;

      Player *player = *info;
      player->advanceMovement(nowMs);
  }
  ```

- [ ] **Step 3: Build**

  Run: `cmake --build --preset game-debug`
  Expected: success.

- [ ] **Step 4: Commit**

  ```bash
  git add src/game/network/game_client_connection.hpp src/game/network/game_client_connection.cpp
  git commit -m "feat(connection): expose advance_player_movement for world tick"
  ```

---

## Task 9: Add world-tick timer to `GameServer`

**Files:**
- Modify: `src/game/server/game_server.hpp` (timer member + constant + method decls)
- Modify: `src/game/server/game_server.cpp` (start, process, cancel)

- [ ] **Step 1: Edit `game_server.hpp`**

  In the `private:` member section (after `signals_`):

  ```cpp
      // World tick: advances moving players' positions on a fixed cadence.
      std::unique_ptr<boost::asio::steady_timer> world_tick_timer_;
      static constexpr std::chrono::milliseconds kWorldTickInterval{100};
  ```

  In the private method section (after `shutdown_server();`):

  ```cpp
      // World tick implementation
      void start_world_tick();
      void process_world_tick(const boost::system::error_code &ec);
  ```

- [ ] **Step 2: Edit `game_server.cpp` — includes**

  Near the top, add (skip if already present):

  ```cpp
  #include "../network/game_client_connection.hpp"
  ```

- [ ] **Step 3: Edit `game_server.cpp` — kick off the tick during start**

  In `GameServer::start()`, after the line `start_accepting();` and before the catch block, add:

  ```cpp
          // Start world tick after accepting begins.
          start_world_tick();
  ```

  The new bottom of the `try` block should read:

  ```cpp
          start_accepting();
          // Start world tick after accepting begins.
          start_world_tick();
  ```

- [ ] **Step 4: Edit `game_server.cpp` — cancel timer in shutdown**

  In `GameServer::shutdown_server()`, after `running_.store(false);` and before the acceptor close block, add:

  ```cpp
      // Cancel world tick first so it stops re-arming.
      if (world_tick_timer_) {
          boost::system::error_code ec;
          world_tick_timer_->cancel(ec);
      }
  ```

- [ ] **Step 5: Edit `game_server.cpp` — implement tick methods**

  Append (or insert near other private methods):

  ```cpp
  void GameServer::start_world_tick()
  {
      world_tick_timer_ = std::make_unique<boost::asio::steady_timer>(io_context_);
      world_tick_timer_->expires_after(kWorldTickInterval);
      world_tick_timer_->async_wait(
          [this](const boost::system::error_code &ec) { process_world_tick(ec); });
      log_server_event("World tick started ("
          + std::to_string(kWorldTickInterval.count()) + "ms interval)");
  }

  void GameServer::process_world_tick(const boost::system::error_code &ec)
  {
      if (ec == boost::asio::error::operation_aborted) {
          return; // cancellation - normal during shutdown
      }
      if (ec) {
          log_server_event("World tick error: " + ec.message());
          return;
      }

      const int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count();

      if (connection_manager_) {
          auto conns = connection_manager_->get_all_connections();
          for (auto &base : conns) {
              try {
                  auto game_conn = std::dynamic_pointer_cast<GameClientConnection>(base);
                  if (game_conn) {
                      game_conn->advance_player_movement(nowMs);
                  }
              } catch (const std::exception &e) {
                  log_server_event(std::string("World tick: per-connection exception: ") + e.what());
              }
          }
      }

      // Re-arm.
      if (running_.load() && world_tick_timer_) {
          world_tick_timer_->expires_after(kWorldTickInterval);
          world_tick_timer_->async_wait(
              [this](const boost::system::error_code &ec) { process_world_tick(ec); });
      }
  }
  ```

- [ ] **Step 6: Build**

  Run: `cmake --build --preset game-debug`
  Expected: success. Server now ticks at 100ms intervals but does nothing visible until a player is moving.

- [ ] **Step 7: Commit**

  ```bash
  git add src/game/server/game_server.hpp src/game/server/game_server.cpp
  git commit -m "feat(server): add 100ms world tick advancing player movement"
  ```

---

## Task 10: Manual smoke verification

**Files:** none — verifies the system end-to-end against the spec's manual verification plan.

Per `CLAUDE.md`, no automated tests are added. This task is the verification gate before declaring movement done.

- [ ] **Step 1: Clean build and run**

  ```bash
  cmake --build --preset game-debug
  ./build/debug/out/l2_game_server
  ```

  Expected: server starts, "World tick started (100ms interval)" appears in startup logs.

- [ ] **Step 2: Smoke - login + enter world**

  Connect with the L2 Interlude client (login server should be running too). Log in with the existing test character. Confirm: loading screen clears, character appears in-world. (This is the pre-existing EnterWorld behavior — no movement involved yet. If this regresses, stop and bisect; movement code should not change EnterWorld.)

- [ ] **Step 3: Smoke - move click works**

  Right-click a spot on the ground.
  Expected in server log:
  - `MoveBackwardToLocation packet received` (or your equivalent — confirm the new handler ran).
  - `MoveBackwardToLocation: dest set to (X, Y, Z)` with the clicked coordinates.
  - Periodic position-progressing (you can add a temporary `log_server_event` inside `process_world_tick` if not already verbose).
  Expected on the client: character visibly walks to the spot and stops.

- [ ] **Step 4: Smoke - cancel via origin == target**

  Click on your character's own feet.
  Expected: `MoveBackwardToLocation: cancel (origin == target)` in log; `ActionFailed` sent; no position change.

- [ ] **Step 5: Smoke - distance cap**

  Click extremely far away on the minimap (or send a crafted packet) so target is > 9900 units from origin.
  Expected: `MoveBackwardToLocation: distance too large - dropping` in log; no movement.

- [ ] **Step 6: Smoke - arrival**

  After a normal walk completes, inspect the player's server-side X/Y/Z (add a temp log in `advanceMovement` at the snap branch if needed). Expected: within 16 units of the requested destination; `isMoving_` is false.

- [ ] **Step 7: Smoke - `ValidatePosition` arrives and is processed**

  While walking, watch for incoming `0x48` opcodes. Add a temporary log in `handle_validate_position_packet` if needed.
  Expected: the server's stored X/Y/Z continues to track the client during travel.

- [ ] **Step 8: Smoke - large-delta snap**

  Provoke a divergence: stop the server-side player mid-walk via debugger (or hardcode `player->setPosition(0,0,0)` after `setMoveDestination` for one run). The next `ValidatePosition` from the client should trigger `ValidateLocation delta too large - sent ValidateLocation` in the log, and the client should snap back.

- [ ] **Step 9: Regression - no EnterWorld regression**

  Restart the server, log in fresh. Confirm EnterWorld sequence still completes (loading screen clears, system message shows, ActionFailed sent).

- [ ] **Step 10: Remove any temporary debug logs added during verification**

  Search for any TODO/temp log lines added in steps 3, 6, 7, 8. Remove them.

- [ ] **Step 11: Final commit**

  ```bash
  git status
  # If any temp-log cleanup commits remain, commit them:
  git add -u
  git commit -m "chore(movement): remove temp verification logs"
  # Otherwise skip - working tree should already be clean.
  ```

- [ ] **Step 12: Push branch**

  ```bash
  git push -u origin feat/player-movement
  ```

- [ ] **Step 13: Open PR**

  ```bash
  gh pr create --title "feat: player movement (authoritative + ValidatePosition)" --body "$(cat <<'EOF'
  ## Summary
  - Handle MoveBackwardToLocation (0x01) - set destination, send MoveToLocation
  - Handle ValidatePosition (0x48) - reconcile client vs server position
  - World-tick timer on GameServer advances moving players (100ms cadence)
  - Fix MoveToLocation to use real destination instead of current position

  Spec: `docs/superpowers/specs/2026-05-22-player-movement-design.md`
  Plan: `docs/superpowers/plans/2026-05-22-player-movement.md`

  ## Test plan
  - [ ] Build clean: `cmake --build --preset game-debug`
  - [ ] Log in + EnterWorld still works (regression)
  - [ ] Click ground - character walks to spot
  - [ ] Click own feet - ActionFailed, no movement
  - [ ] Click > 9900 units away - ActionFailed, no movement
  - [ ] Arrival - server X/Y/Z within 16 units of target, isMoving = false
  - [ ] ValidatePosition keeps server X/Y/Z synced during walk

  🤖 Generated with [Claude Code](https://claude.com/claude-code)
  EOF
  )"
  ```

---

## Self-review notes

**ReadablePacket interface verified** against `src/core/packets/packet.hpp` and `src/game/packets/requests/request_show_mini_map.{hpp,cpp}`. Three pure virtuals: `getPacketId()`, `getExPacketId()`, `read(ReadablePacketBuffer&)`. Tasks 3 and 4 now include all three overrides.

**Factory helper pattern verified** against `createNoOpPacket`, `createProtocolVersionPacket`, `createAuthLoginPacket` in `packet_factory.cpp` — all follow the same try/catch + `ReadablePacketBuffer` + `make_unique` + `read` pattern, throwing `PacketException` on failure. Task 5 step 5 matches that pattern exactly.

**Player lifecycle verified**: `CharacterDatabaseManager` owns `unique_ptr<Player>` per character ID and hands out raw `Player*` via `getCharacterById`/`getCharacterBySlot`. The same pointer is returned across calls, so state set by `setMoveDestination` in one packet handler persists for the world tick. This is why the connection doesn't need to own a player — the lookup is the source of truth.

**World-tick interval** is fixed at 100ms (`kWorldTickInterval`). If Task 10 step 3 shows visible drift between client render and server position, dropping to 50ms is a one-line tuning change and intentionally not in this plan.

**Heading sign convention**: L2 heading 0 points toward +X. `atan2(dy, dx)` returns radians with the same convention (0 = +X axis). Mapping to 16-bit via `radians * 32768/pi` gives the expected client heading. Negative values get normalized into `[0, 65535]` by the `& 0xFFFF` mask.

**Not covered (deliberate)**:
- `StopMove` server packet — client stops on its own from the MoveToLocation endpoints we sent. Add only if smoke testing shows drift on arrival.
- Geodata / pathfinding / walkability — no geodata exists in this project.
- Multi-client visibility / broadcast — solo scope per spec; would require a knownlist/region system.
- `Player::getRunSpeed()` is hardcoded to 120 today. That's fine — when it becomes dynamic, `advanceMovement` picks up the change automatically.
