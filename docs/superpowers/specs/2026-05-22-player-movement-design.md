# Player movement — design

**Status:** approved (brainstorm complete, awaiting implementation plan)
**Date:** 2026-05-22
**Branch:** `feat/enter-world-ground-work` (continues from `d0702cd feat: Enter world (finally)`)

## Goal

Make the player visibly walk to a clicked location, with the **server as the authoritative source of position**. Server simulates movement on a tick and reconciles against the client via `ValidatePosition`.

Out of scope this round: other players or NPCs visible to this player, geodata, pathfinding, `StopMove` server packet, vehicle/mount movement, swimming, fall damage.

## What already exists

- `MoveToLocation` server→client response packet (opcode `0x01`) at `src/game/packets/responses/move_to_location.{hpp,cpp}`. **Bug to fix**: destination fields (`xDst/yDst/zDst`) currently default to the player's current X/Y/Z (TODO comments in the .cpp).
- `ValidateLocation` server→client response packet (opcode `0x61`) — already used in the EnterWorld sequence.
- Client opcode `MoveBackwardToLocation = 0x01` enumerated in `GameClientPacketType`; the factory routes it to a `NoOpPacket` and the connection handler only logs it.
- `WorldObject` exposes `x_, y_, z_, heading_` with getters and `setPosition` / `setHeading`.
- `Player::getRunSpeed()` returns hardcoded `120`, `Player::getWalkSpeed()` returns `50`, `Player::isRunning()` returns `true`.
- `GameServer` already owns a `boost::asio::io_context_`; no world-tick timer yet.
- `BaseConnectionManager` exposes `broadcast_packet(...)` and `broadcast_to_state(...)`, but solo-only scope means we send directly to the moving connection.

## Architecture

Two cooperating layers, both additive:

1. **Packet / state layer** — three new request packets, one fix to an existing response, and new fields/methods on `Player`. No infrastructure changes.
2. **World-tick layer** — a single `boost::asio::steady_timer` on `GameServer`, posted onto the existing `io_context_`. On each tick it iterates connected `GameClientConnection`s and asks each to advance its `Player` toward destination. No threads added.

The two layers do not depend on each other to compile. If the tick is disabled, the client will still animate locally from the destination it received; the tick only keeps the server's authoritative coordinates correct.

## Components

### New request packets

**`MoveBackwardToLocationPacket`** — `src/game/packets/requests/move_backward_to_location_packet.{hpp,cpp}`, opcode `0x01`.
Reads 7 × `int32`: `targetX, targetY, targetZ, originX, originY, originZ, movementMode`.

**`ValidatePositionPacket`** — `src/game/packets/requests/validate_position_packet.{hpp,cpp}`, opcode `0x48`.
Reads 5 × `int32`: `x, y, z, heading, vehicleId` (vehicleId discarded — no vehicles in scope).

### Enum + factory changes

In `src/game/packets/packet_factory.hpp`:
- Add `ValidatePosition = 0x48` to `GameClientPacketType`.

In `src/game/packets/packet_factory.cpp`:
- Replace the `createNoOpPacket` call for `MoveBackwardToLocation` with a new `createMoveBackwardToLocationPacket`.
- Add a case for `ValidatePosition` that calls a new `createValidatePositionPacket`.
- Declare both `create*` helpers in the header.

### Existing response fix

In `src/game/packets/responses/move_to_location.cpp`, the constructor currently does:

```cpp
m_xDst(player->getX()),  // TODO
m_yDst(player->getY()),  // TODO
m_zDst(player->getZ())   // TODO
```

Replace with `player->getDestX()/getDestY()/getDestZ()`. Same byte layout — only the source values change.

### `Player` extensions

New fields:

```cpp
int32_t xDst_ = 0, yDst_ = 0, zDst_ = 0;
bool isMoving_ = false;
int64_t lastMoveTickMs_ = 0;

// Mirror of what the client thinks (updated by ValidatePosition).
// Stored now so future code (combat, casting) can ask cheaply.
int32_t clientX_ = 0, clientY_ = 0, clientZ_ = 0;
int32_t clientHeading_ = 0;
```

New methods:

- `int32_t getDestX() const`, `getDestY()`, `getDestZ()` — accessors used by `MoveToLocation::write`.
- `bool isMoving() const`.
- `void setMoveDestination(int32_t x, int32_t y, int32_t z, int64_t nowMs)` — sets dest, computes heading from origin→dest as `static_cast<int32_t>(atan2(dy, dx) * 32768.0 / π) & 0xFFFF` (L2 uses a 16-bit angle: 0..65535 covering one full turn), sets `isMoving_=true`, sets `lastMoveTickMs_=nowMs`.
- `void stopMove()` — clears `isMoving_`, leaves position where it is.
- `void advanceMovement(int64_t nowMs)` — if `!isMoving_` returns; otherwise computes `dt = nowMs - lastMoveTickMs_`, clamps `dt` to `[0, 1000]` ms (defends against first tick and pathological pauses), `lastMoveTickMs_ = nowMs`, advances `x_,y_,z_` toward dest by `min(runSpeed * dt / 1000, remaining_distance)`. If remaining < 16 units (matches Mobius geodata-cell epsilon), snaps to dest and calls `stopMove()`.
- Client-mirror setters: `setClientPosition(x,y,z)`, `setClientHeading(h)`.

### `GameClientConnection` extensions

In `src/game/network/game_client_connection.{hpp,cpp}`:

- `handle_move_backward_to_location_packet(std::unique_ptr<ReadablePacket>& packet)`.
- `handle_validate_position_packet(std::unique_ptr<ReadablePacket>& packet)`.
- `void advance_player_movement(int64_t nowMs)` — public; delegates to `player_->advanceMovement(nowMs)` when a player is attached and the connection is in `InGame`.
- In `handle_game_packet()`'s opcode switch, replace the `0x01` log-only stub and add a `0x48` case to call these handlers.

### `GameServer` extensions

In `src/game/server/game_server.{hpp,cpp}`:

- New members:
  ```cpp
  std::unique_ptr<boost::asio::steady_timer> world_tick_timer_;
  static constexpr std::chrono::milliseconds kWorldTickInterval{100};
  ```
- `void start_world_tick()` — called once at the end of `initialize_server()` / `start_accepting()`. Constructs the timer on `io_context_`, sets first expiry, calls `process_world_tick` on completion.
- `void process_world_tick(const boost::system::error_code& ec)` — on `ec == operation_aborted` (cancelled) return; on other errors log + return. Else: read `now` (ms since epoch from `steady_clock`), iterate connections via `connection_manager_`, call `advance_player_movement(now)` on each `GameClientConnection`. Catch and log per-connection exceptions so one bad connection doesn't kill the tick. Re-arm `world_tick_timer_` for another `kWorldTickInterval`.
- `shutdown_server()` cancels `world_tick_timer_` alongside the acceptor.

### File list (new) / file list (modified)

**New (8 files):**
- `src/game/packets/requests/move_backward_to_location_packet.hpp`
- `src/game/packets/requests/move_backward_to_location_packet.cpp`
- `src/game/packets/requests/validate_position_packet.hpp`
- `src/game/packets/requests/validate_position_packet.cpp`

**Modified:**
- `src/game/packets/packet_factory.hpp` — enum + create-helper decls.
- `src/game/packets/packet_factory.cpp` — route opcodes `0x01` and `0x48`.
- `src/game/packets/responses/move_to_location.cpp` — use real dest accessors.
- `src/game/entities/player.hpp` / `.cpp` — new fields, getters, `setMoveDestination`, `stopMove`, `advanceMovement`, client-mirror setters.
- `src/game/network/game_client_connection.hpp` / `.cpp` — two handlers + `advance_player_movement`, opcode switch wiring.
- `src/game/server/game_server.hpp` / `.cpp` — world-tick timer.
- `CMakeLists.txt` — add the 4 new `.cpp` sources (sources are listed explicitly, no glob).

## Data flow

### Move click (one-shot)

```
Client right-click on ground
  → MoveBackwardToLocation (0x01) { targetX,Y,Z, originX,Y,Z, movementMode }
GameClientConnection::handle_move_backward_to_location_packet
  validate state == InGame                              (else: drop + ActionFailed)
  early-out origin==target  → player->stopMove() + ActionFailed
  early-out dx²+dy² > 9900² → ActionFailed
  player->setMoveDestination(targetX, targetY, targetZ, now)
  this->send_packet(std::make_unique<MoveToLocation>(player))   // to self only (solo scope)
                                                                // uses real getDestX/Y/Z now
```

### World tick (every ~100 ms)

```
GameServer::process_world_tick(now)
  for each conn in connection_manager_:
    try { conn->advance_player_movement(now) } catch (...) { log; continue }
      player->advanceMovement(now)
        if !isMoving_ return
        dt = clamp(now - lastMoveTickMs_, 0, 1000); lastMoveTickMs_ = now
        step = (runSpeed * dt) / 1000
        advance (x_,y_,z_) toward (xDst_,yDst_,zDst_) by min(step, remaining)
        if remaining < 16: snap to dest, isMoving_ = false
re-arm world_tick_timer_
```

The tick emits no packets. The client has both endpoints from the original `MoveToLocation` and animates locally.

### Position reconciliation (every ~1 s from the client)

```
Client → ValidatePosition (0x48) { x, y, z, heading, vehicleId }
GameClientConnection::handle_validate_position_packet
  validate state == InGame  (else: drop silently — these packets are noisy)
  delta² = (clientX - serverX)² + (clientY - serverY)²
  if delta² < 360 000:                                  // ≈600 units
    trust client: player->setPosition(x, y, z); setHeading(heading)
  else:
    send ValidateLocation(player)                       // snap client back
  always: player->setClientPosition(x,y,z); setClientHeading(heading)
```

## Error handling

**`MoveBackwardToLocation`**
- Wrong state → drop + `ActionFailed`.
- Player not attached → drop + `ActionFailed`, log.
- Origin == target → `stopMove()` + `ActionFailed` (Mobius behavior — this is "cancel move").
- `dx²+dy² > 98 010 000` → drop + `ActionFailed` (anti-exploit, matches Mobius).

**`ValidatePosition`**
- Wrong state → drop silently.
- Player not attached → drop silently.
- Small delta → trust client, update server X/Y/Z.
- Large delta → don't update server pos, send `ValidateLocation(player)`.

Mobius's geodata Z-fall handling, door checks, and zone (water/flying) branches are **all skipped** — no geodata in this project.

**World tick**
- Timer error code `operation_aborted` → don't re-arm. Other errors → log + don't re-arm.
- Per-connection exception → catch + log + continue with next connection.
- `dt` clamping to `[0, 1000]` ms guards first-tick (`lastMoveTickMs_==0`) and long pauses.

**Connection lifecycle**
- On disconnect, the connection drops out of the manager before the next tick iterates. No special movement cleanup needed; `Player` is owned by the connection and dies with it.

No new exception types, no new error responses — everything reuses `ActionFailed` / `ValidateLocation` / `log_connection_event`.

## Testing

Per `CLAUDE.md` ("do not write tests unless explicitly asked"), this is a **manual verification plan**, not new automated tests.

**Build**
- `cmake --build --preset game-debug` succeeds with no new warnings.
- All 4 new `.cpp` files appear in `CMakeLists.txt`.

**Smoke run**
- Start `l2_game_server`, log in with the existing test character that already enters world.
- **Move click**: right-click ground. Expect character visibly walks to the spot. Server log shows `MoveBackwardToLocation` received, `MoveToLocation` sent with destination matching the click, and per-tick movement progressing.
- **Arrival**: after walking, server-stored player X/Y/Z is within 16 units of the requested destination and `isMoving_` is false.
- **Cancel via origin==target**: click on your own feet. Expect `ActionFailed`, no position change.
- **Huge distance**: send a target 20k+ units away (manual edit or replay). Expect `ActionFailed`, no movement.
- **ValidatePosition reconcile**: walk for a few seconds; server X/Y/Z should converge as `ValidatePosition` packets arrive. Forcing a large server/client divergence should trigger a `ValidateLocation` back to the client.

**Regression**
- EnterWorld still completes (loading screen still clears). Movement code must not change the EnterWorld packet sequence.
- Existing handlers (`Say2`, `Action`, `RequestItemList`, `RequestShowMiniMap`) still work — the opcode switch only adds cases.

**Explicitly not verified this round**
- Geodata walkability (no geodata exists).
- Pathfinding around obstacles.
- Multi-client visibility (solo-only by design).
- `StopMove` server packet (client stops on its own from `MoveToLocation` endpoints; add only if drift becomes visible).
