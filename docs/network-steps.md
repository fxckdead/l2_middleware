# Lineage 2 Login Server - Cryptographic Flow

This document outlines the complete step-by-step cryptographic flow for the Lineage 2 login server implementation, showing exactly what is received and sent at each stage.

## Phase 1: Client Connection to Login Server

### Step 1: Initial Connection
```
[recv] Client connects to login server (TCP handshake)
[sent] Login server sends Init packet:
       - Opcode: 0x00 (Init)
       - Session ID: random i32
       - Protocol revision: 0x0000c621
       - RSA public key: 129 bytes (scrambled modulus)
       - GameGuard data: 16 bytes of constants
       - Blowfish key: 16 bytes (random generated)
       - Null terminator: 1 byte
```

### Step 2: GameGuard Authentication (Optional)
```
[recv] Client sends RequestAuthGG:
       - Opcode: 0x07
       - Session ID: i32 (must match server's session ID)
       - Additional data: 16 bytes (GameGuard related)
       ** Packet is Blowfish encrypted (except first packet) **

[sent] Login server sends AuthGG response:
       - Opcode: 0x0B (GgAuth) 
       - Session ID: i32 (echo back)
       - Padding: 16 bytes of zeros
       ** Packet is Blowfish encrypted **
```

### Step 3: Login Credentials
```
[recv] Client sends RequestAuthLogin:
       - Opcode: 0x00
       - Username/Password: 128 bytes (RSA encrypted block 1)
       - [Optional] Additional data: 128 bytes (RSA encrypted block 2 for newer clients)
       ** RSA encryption with server's public key **
       ** No Blowfish encryption for credentials **

Server processes:
1. RSA decrypt the 128-byte block(s)
2. Extract username from offset 0x5E (old) or 0x4E+0xCE (new)
3. Extract password from offset 0x6C (old) or 0xDC (new)
4. Validate against database
5. Generate session key (4 random i32 values)

[sent] Login server sends response:
       ** If show_license = true **
       - LoginOk packet:
         - Opcode: 0x03
         - login_ok1: i32
         - login_ok2: i32
         - Padding: 32 bytes
       ** If show_license = false **
       - ServerList packet (see Step 4)
       ** Packet is Blowfish encrypted **
```

### Step 4: Server List Request
```
[recv] Client sends RequestServerList:
       - Opcode: 0x05
       - login_ok1: i32 (from session key)
       - login_ok2: i32 (from session key)
       ** Packet is Blowfish encrypted **

[sent] Login server sends ServerList:
       - Opcode: 0x04
       - Server count: u8
       - Last server: u8
       - For each server:
         - Server ID: u8
         - IP address: 4 bytes
         - Port: i32
         - Age limit: u8
         - PvP flag: bool
         - Current players: i16
         - Max players: i16
         - Status: bool
         - Server type: i32
         - Show brackets: bool
       - Character count data: variable
       ** Packet is Blowfish encrypted **
```

### Step 5: Game Server Selection
```
[recv] Client sends RequestGSLogin:
       - Opcode: 0x02
       - s_key_1: i32 (must match session.login_ok1)
       - s_key_2: i32 (must match session.login_ok2)
       - server_id: u8
       ** Packet is Blowfish encrypted **

[sent] Login server sends PlayOk:
       - Opcode: 0x07
       - play_ok1: i32 (from session key)
       - play_ok2: i32 (from session key)
       ** Packet is Blowfish encrypted **
```

## Phase 2: Game Server Communication

### Step 6: Game Server to Login Server Handshake
```
[sent] Login server sends InitLS to game server:
       - Opcode: 0x00
       - Protocol revision: i32
       - Key length: i32
       - RSA public key: variable bytes (unscrambled modulus)
       ** No encryption initially **

[recv] Game server sends BlowFish key exchange:
       - Opcode: 0x00
       - Key length: i32
       - Encrypted Blowfish key: 128 bytes (RSA encrypted with LS public key)
       ** RSA encryption using login server's public key **

Game server processes:
1. Generate 40-byte Blowfish key
2. RSA encrypt the key with login server's public key
3. Send encrypted key
4. Start using Blowfish for subsequent packets

[recv] Game server sends RequestAuthGS:
       - Opcode: 0x01 
       - Server ID: u8
       - Accept alternative ID: bool
       - Host reserved: bool
       - Port: u16
       - Max players: u32
       - Hex ID: 16 bytes
       - Host configuration: variable
       ** Packet is Blowfish encrypted + checksum **

[sent] Login server sends AuthGS response:
       - Opcode: 0x00
       - Server ID: u8 (assigned ID)
       - Server name: string
       ** Packet is Blowfish encrypted + checksum **
```

## Phase 3: Client to Game Server Authentication

### Step 7: Client Connects to Game Server
```
[recv] Client connects to game server
[sent] Game server sends ProtocolVersion:
       - Opcode: varies
       - Protocol info and encryption key
       ** Uses GameClientEncryption (XOR-based) **
```

### Step 8: Player Authentication Request
```
[recv] Game server receives AuthLogin from client:
       - Opcode: 0x2B
       - Username: string (UTF-16LE)
       - play_key_2: i32 (from login server's PlayOk)
       - play_key_1: i32 (from login server's PlayOk) 
       - login_key_1: i32 (from login server's PlayOk)
       - login_key_2: i32 (from login server's PlayOk)
       ** GameClientEncryption (XOR) + checksum **

[sent] Game server sends PlayerAuthRequest to login server:
       - Opcode: 0x05
       - Username: string (UTF-16LE)
       - Session key: SessionKey struct (all 4 i32 values)
       ** Blowfish encryption + checksum **

[recv] Login server sends PlayerAuthResponse:
       - Opcode: varies
       - Username: string
       - Success: bool
       ** Blowfish encryption + checksum **

[sent] Game server sends PlayerLoginResponse to client:
       - Success/failure response
       ** GameClientEncryption (XOR) + checksum **
```

## Phase 4: Ongoing Communication

### Step 9: Regular Packet Flow

**Login Server ↔ Game Server:**
```
All packets use:
1. 2-byte length header (unencrypted)
2. Packet data (Blowfish encrypted)
3. 4-byte checksum (included in encrypted data)
4. Padding to 8-byte boundary for Blowfish
```

**Client ↔ Game Server:**
```
All packets use:
1. 2-byte length header (unencrypted)  
2. Packet data (GameClientEncryption XOR)
3. 4-byte checksum (included in encrypted data)
4. Dynamic key updates based on packet length
```

**Client ↔ Login Server:**
```
All packets use:
1. 2-byte length header (unencrypted)
2. Packet data (Blowfish encrypted)  
3. 4-byte checksum (included in encrypted data)
4. Padding to 8-byte boundary for Blowfish
```

## Encryption Processing Order

### Outgoing Packets:
```
1. Build packet content
2. Add 4-byte checksum to end
3. Apply encryption (Blowfish or GameClientEncryption)
4. Add 2-byte length header
5. Send over TCP
```

### Incoming Packets:
```
1. Receive TCP data
2. Read 2-byte length header
3. Apply decryption (Blowfish or GameClientEncryption)
4. Verify 4-byte checksum
5. Parse packet content
6. Handle packet logic
```

## Security Features Summary

1. **RSA Encryption**: 1024-bit keys for initial secure key exchange
2. **Blowfish Encryption**: Fast symmetric encryption for login server communication
3. **GameClientEncryption**: XOR-based encryption for game server communication
4. **Session Keys**: 4 random i32 values for server handoff authentication
5. **Checksum Verification**: 4-byte CRC for packet integrity
6. **Key Scrambling**: RSA modulus obfuscation to prevent reverse engineering
7. **Layered Security**: Multiple encryption layers provide defense in depth

This flow ensures secure communication at every step while maintaining the performance needed for real-time gaming. 