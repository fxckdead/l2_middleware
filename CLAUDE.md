# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

A C++20 TCP server emulating Lineage 2 (Interlude / "746 Interlude Update 3" protocol).
It is a port/reimplementation guided by a known Rust L2 emulator — `.cursor/rules/`
and code comments refer to that as "the RUST project". L2J Mobius CT_0 Interlude
(Java) is also used as a reference for packet opcodes and byte layouts. Two
executables share one static core library: a **Login server** (auth, server list)
and a **Game server** (character selection, world entry, gameplay).

## Build & run

Requires `VCPKG_ROOT` set; dependencies (boost-asio, openssl, nlohmann-json) install
automatically on first configure. Ninja is the configured generator.

```bash
cmake --preset debug              # configure -> build/debug/
cmake --build --preset debug      # build everything
cmake --build --preset game-debug # build only L2GameServer (also: login-debug, core-debug)
cmake --preset release && cmake --build --preset release
```

Executables land in `build/<debug|release>/out/` as `l2_login_server` and
`l2_game_server`. Default ports: 2106 (login), 7777 (game).

## Tests

Test sources live in `src/core/tests/` and `src/login/tests/` but are **not wired
into CMakeLists.txt** — there is no test build target and no test framework
(GTest/Catch2). Tests are plain `void test_*()` functions aggregated by
`all_core_tests.cpp` / `all_login_tests.cpp` via `#include` of `.cpp` files.
To run them you must add a target manually. Per the project rules, **do not write
tests unless explicitly asked.**

## Architecture

Three layers, mirrored by the `src/core`, `src/login`, `src/game` directories:

- **core** — shared abstractions. `BaseClientConnection` / `BaseConnectionManager`
  (boost::asio networking), the packet system, and encryption (`RsaManager`,
  Blowfish, XOR `GameClientEncryption`, `L2Checksum`).
- **login** — `LoginServer` wires a `LoginConnectionManager` that produces
  `LoginClientConnection`s; tracks registered game servers via `GameServerManager`.
- **game** — `GameServer` + `GameConnectionManager` + `GameClientConnection`;
  characters via `CharacterDatabaseManager`; world via `entities/` (`WorldObject`
  → `Creature` → `Player`).

### Packet system

All packets implement `ReadablePacket` (client→server) or `SendablePacket`
(server→client) from `src/core/packets/packet.hpp`. Serialization goes through
`ReadablePacketBuffer` / `SendablePacketBuffer` (`src/core/network/packet_buffer.hpp`).

A **`PacketFactory`** per server (`src/login/packets/packet_factory.cpp`,
`src/game/packets/packet_factory.cpp`) maps opcodes to packet objects and centralizes
RSA/decryption concerns. Opcodes are enumerated in the factory headers
(`GameClientPacketType`, `ExtendedGamePacketType` — extended packets are `0xD0`
followed by a 16-bit sub-opcode).

Each connection drives a strict **state machine**: `LoginClientConnection::LoginState`
and `GameClientConnection::GameState`. Handlers validate the current state before
processing and transitions are checked (`validate_game_state_transition`).

**Verify opcodes against L2J Mobius CT_0 Interlude.** Server `PACKET_ID` constants
in `src/game/packets/responses/*.hpp` must match `gameserver/network/ServerPackets.java`.
Client opcodes in `GameClientPacketType` / `ExtendedGamePacketType` must match
`ClientPackets.java` / `ExClientPackets.java`. Wrong opcodes don't fail the build —
they cause the client to misinterpret packets at runtime. Precedent: `UserInfo`
was `0x32`, which is `ASK_JOIN_PLEDGE`, so the client read it as a clan-invite
dialog and the EnterWorld loading screen never cleared.

### Adding a packet (canonical workflow)

1. Create `<name>.hpp/.cpp` under `requests/` or `responses/` of the relevant server.
2. Register the opcode and construction in that server's `PacketFactory`.
3. Add a `handle_*` method on the connection class and route it in
   `handle_complete_packet()` / `handle_game_packet()`.
4. **Add the new `.cpp` to `CMakeLists.txt`** — sources are listed explicitly,
   there is no glob.
5. Verify the opcode against Mobius's `ServerPackets.java` (for responses) or
   `ClientPackets.java` / `ExClientPackets.java` (for requests).

### Login authentication flow

`Init` (RSA keys + Blowfish key) → `AuthLogin` (validate creds, **generate and store
session keys via `set_session_key`**) → `RequestAuthGG` → `RequestServerList` →
`RequestGSLogin` (validates stored session keys) → `PlayOk`. The session key must be
stored on the connection or `RequestGSLogin` validation fails.

### Game server encryption (XOR — important and subtle)

The game server uses XOR `GameClientEncryption` for legacy/patched Interlude clients
(Blowfish is the alternative; see `GameClientConnection::initialize_encryption`).

- `VersionCheck` (opcode `0x00`) is sent **unencrypted, exactly 27 bytes** of payload.
- The 16-byte XOR key = first 8 bytes you sent in `VersionCheck` concatenated with
  the immutable static tail `C8 27 93 01 A1 6C 31 97`. Build it **once**.
- Strip the 2-byte length header **before** `decrypt()`; encryption starts at the
  first post-header byte (`key index = i % 16`).
- Chaining XOR: `data[i] = enc ^ key[i % 16] ^ xOr; xOr = enc;` (swap order to encrypt).
- Rotate `key[8..11]` by `delta = payload_size` (header and padding excluded).
- XOR packets pad to a multiple of 4; Blowfish pads to 8.
- Never log/dispatch an opcode before decryption — refresh `opcode = data[0]` after.

## Conventions (from .cursor/rules)

- Naming: `PascalCase` types, `camelCase` methods/vars, `SCREAMING_SNAKE_CASE`
  constants, `_member` or `m_member` for fields. Modern C++20: smart pointers,
  `std::optional`/`std::variant`, `std::string_view`, `enum class`, RAII.
- **Prefer composition over inheritance.**
- PacketBuffer method names are case-sensitive and a frequent build-error source:
  `SendablePacketBuffer` uses `writeUInt8()` (capital U), `writeInt32()`;
  `ReadablePacketBuffer` uses `readByte()` for `uint8_t`, `readInt32()`.
- Working style: small incremental steps; ask before any change touching >5 files
  or restructuring the project. Don't claim something is fixed until confirmed by a
  build or run — code changes alone are not confirmation.

## Debugging helpers

- `PacketUtils::hexDump(data, "[Prefix] ")` (in `src/core/packets/packet.cpp`) —
  hex/ASCII dump of raw packet bytes.
- `CreateCharRequestPacket::toString()` — logs parsed character fields.
- Reference docs in `docs/` cover opcodes (`746-interlude-update3-opcodes.md`),
  the network handshake, and the XOR bug fix.
