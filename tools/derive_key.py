import hashlib, struct, sys

# --- Step 1: raw materials extracted from VoiSona.exe ---
# 16-byte key string @ .rdata VMA 0x140F340F8 (15 chars + NUL)
KEY_STR = b'TSVoiceEncKey001'
# 32-byte table @ 0x140F340D8 = SHA-256 IV constants (8 x u32 LE)
TABLE_BYTES = bytes.fromhex(
    '67E6096A85AE67BB72F36E3C3AF54FA57F520E518C68059BABD9831F19CDE05B')
IV = struct.unpack('<8I', TABLE_BYTES)

MASK = 0xFFFFFFFF

def fmix32(x):
    x &= MASK
    x ^= x >> 16
    x = (x * 0x45D9F3B) & MASK
    x ^= x >> 16
    x = (x * 0x45D9F3B) & MASK
    x ^= x >> 16
    return x & MASK

# --- Step 2: reproduce disassembly loop @ 0x140412480 ---
# for i in 0..7: intermediate[i] = fmix32(i * 0x9E3779B9 XOR table[i]), stored u32 LE
intermediate = b''.join(
    struct.pack('<I', fmix32((i * 0x9E3779B9) ^ IV[i])) for i in range(8))

# --- Step 3: key = BLAKE2b-256(data=intermediate, key="TSVoiceEncKey001") ---
# (crypto_generichash(out,32, in,32, key,16) => blake2b-256 keyed)
derived = hashlib.blake2b(intermediate, key=KEY_STR, digest_size=32).digest()

print('key string     :', KEY_STR.decode())
print('IV table (u32) :', [f'0x{v:08X}' for v in IV])
print('intermediate   :', intermediate.hex().upper())
print()
print('DERIVED KEY    :', derived.hex().upper())
print('len            :', len(derived))

# cross-check with an independent implementation (pycryptodome BLAKE2b-256 keyed)
try:
    from Crypto.Hash import BLAKE2b
    h = BLAKE2b.new(digest_bits=256, key=KEY_STR)
    h.update(intermediate)
    ok = (h.digest() == derived)
    print('cross-check (pycryptodome BLAKE2b-256):', 'MATCH' if ok else 'MISMATCH')
except ImportError:
    print('cross-check: pycryptodome not installed (skipped)')

with open(r'C:\Users\abc\Desktop\dev\qaz123\voisona_dump\TSVoiceEncKey001.bin', 'wb') as f:
    f.write(KEY_STR)
with open(r'C:\Users\abc\Desktop\dev\qaz123\voisona_dump\derived_key.bin', 'wb') as f:
    f.write(derived)
with open(r'C:\Users\abc\Desktop\dev\qaz123\voisona_dump\intermediate.bin', 'wb') as f:
    f.write(intermediate)
print('files written: TSVoiceEncKey001.bin, intermediate.bin, derived_key.bin')
