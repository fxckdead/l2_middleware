# Fixing the "Byte-8 XOR Corruption" Bug

> How we traced a subtle Lineage II XOR key-mismatch that ruined character-creation packets – and the two-line patch that solved it.

---

## TL;DR

* **Symptom** – every game-server packet decrypted fine for the first 7 bytes, then turned to garbage. Character names were truncated, all integer fields became nonsense.
* **Root causes**  
  1. We rotated the XOR key by an incorrect delta (+2 bytes) ⇒ the key drifted each packet.  
  2. The client expects the *second* half of the 16-byte key to be a **static tail** (hard-coded in the executable). We were sending 16 dynamic bytes, so indexes 8-15 never matched.  
  3. Our packet parser then tried to "skip the opcode" twice, throwing the structure off.
* **Fix** – build the key as `[dynamic[0‥7] || STATIC_TAIL]`, rotate it by `payload.size()` exactly, and start parsing at offset 0.
* **Result** – full UTF-16 names arrive intact (`parrita`), race/sex/class decode correctly, and the login flow continues.

---

## 1  The Bug in the Wild

Players reported that new characters always spawned with broken names and random attributes.  A quick look at our verbose logs showed suspicious patterns:

```
Decrypted (first 16 bytes): 0B 70 00 61 00 72 00 72 9E …
                       ^ good ↑           bad from here ↑
```

The first 8 bytes (opcode + `"parr"` in UTF-16LE) were fine, byte 8 and beyond looked XOR-corrupted.

---

## 2  Reproducing & Instrumenting

We added packet-level diagnostics:

```cpp
printf("[XOR] DEC size=%zu hdr=%s delta=%u key8-11 before=%08X after=%08X\n", ...);
```

and a hex-dump right after decryption.  Logs confirmed:

* Key rotation used **delta = 67** for a 65-byte packet ( +2 header bytes ).
* The decrypted stream always broke exactly when key-index switched from 0-7 to 8-15.

---

## 3  Finding the Delta Mismatch

In the original Rust reference (`l2-core/src/crypt/game.rs`) the mutable DWORD at `key[8:12]` is incremented by `payload.len()` – **not including** the 2-byte length header (already stripped in our reader).  Our C++ port mistakenly added those 2 bytes back.

**Fix #1** – in `GameClientEncryption::decrypt/encrypt`:

```diff
- uint32_t delta = has_header ? size : size + 2;
+ uint32_t delta = static_cast<uint32_t>(size);
```

After that change `delta=65` – drift gone, but corruption remained.

---

## 4  The Static-Tail Revelation

Byte-8 corruption hinted that the *second* 8 bytes of the key were wrong.  A disassembly of the Interlude client showed:

```asm
MOV     EAX,[ESI+8]      ; DWORD at offset 8 is the mutable counter
ADD     EAX,PacketSize
```

`key[8..15]` is initialised as **`C8 27 93 01 A1 6C 31 97`** before that code – a constant baked into the binary.

We, however, sent one 16-byte dynamic key in `VersionCheck`.  Result: indexes 8-15 never matched → every XOR after the first block was off.

**Fix #2** – merge the static tail:

```cpp
static const std::array<uint8_t,8> STATIC_TAIL = {
    0xC8,0x27,0x93,0x01,0xA1,0x6C,0x31,0x97
};
std::vector<uint8_t> full_key(16);
std::copy(dynamic.begin(), dynamic.begin()+8, full_key.begin());
std::copy(STATIC_TAIL.begin(), STATIC_TAIL.end(), full_key.begin()+8);
```

Applied in `GameClientConnection::initialize_encryption` before constructing `GameClientEncryption`.

---

## 5  Parser Off-by-One

While testing we also discovered our `CreateCharRequestPacket` reader started at `data_offset = 1` (under the false assumption that the opcode was still present).  The factory had already removed it.

```diff
- size_t data_offset = 1; // Skip opcode
+ size_t data_offset = 0; // Name begins immediately
```

---

## 6  Verification

New log after both patches:

```
[XOR] DEC size=65 delta=65 key8-11 before=0193282F after=01932870
Decrypted: 0B 70 00 61 00 72 00 72 00 69 00 74 00 61 00 00 …
[CreateCharRequestPacket] Name: 'parrita'
Race: 4   Sex: 1   ClassID: 53
```

No stray bytes, checksum passes, character creation succeeds.

---

## 7  Takeaways

* **Always replicate the client's key-material rules.** In Interlude the XOR key is *half dynamic, half static*.
* Keep header-stripping consistent – if the networking layer removes it, cryptographic layers must not compensate for it.
* Early, verbose logging (`delta`, key snapshots, packet hex) is priceless – five minutes of log noise saved hours of guesswork.

Happy hacking, and may your XOR never drift again! 🎮🔐 