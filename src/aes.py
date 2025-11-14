# This file implements the AES (Rijndael) block cipher.
# It supports AES-128, AES-192, and AES-256 by varying the key size.

from src.aes_common import S_BOX, INV_S_BOX, RCON, gmul

# Type alias for the 4x4 byte state matrix
State = list[list[int]]

def _sub_bytes(state: State) -> None:
    """Applies the S-box to each byte of the state."""
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]

def _inv_sub_bytes(state: State) -> None:
    """Applies the inverse S-box to each byte of the state."""
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]

def _shift_rows(state: State) -> None:
    """
    Cyclically shifts the rows of the state.
    Row 0: no shift
    Row 1: 1 byte left shift
    Row 2: 2 bytes left shift
    Row 3: 3 bytes left shift
    """
    # Row 1: [1,0] [1,1] [1,2] [1,3] -> [1,1] [1,2] [1,3] [1,0]
    state[1][0], state[1][1], state[1][2], state[1][3] = \
    state[1][1], state[1][2], state[1][3], state[1][0]
    
    # Row 2: [2,0] [2,1] [2,2] [2,3] -> [2,2] [2,3] [2,0] [2,1]
    state[2][0], state[2][1], state[2][2], state[2][3] = \
    state[2][2], state[2][3], state[2][0], state[2][1]

    # Row 3: [3,0] [3,1] [3,2] [3,3] -> [3,3] [3,0] [3,1] [3,2]
    state[3][0], state[3][1], state[3][2], state[3][3] = \
    state[3][3], state[3][0], state[3][1], state[3][2]

def _inv_shift_rows(state: State) -> None:
    """
    Inverse of ShiftRows (cyclical right shifts).
    Row 0: no shift
    Row 1: 1 byte right shift
    Row 2: 2 bytes right shift
    Row 3: 3 bytes right shift
    """
    # Row 1: [1,0] [1,1] [1,2] [1,3] -> [1,3] [1,0] [1,1] [1,2]
    state[1][0], state[1][1], state[1][2], state[1][3] = \
    state[1][3], state[1][0], state[1][1], state[1][2]
    
    # Row 2: [2,0] [2,1] [2,2] [2,3] -> [2,2] [2,3] [2,0] [2,1] (same as left)
    state[2][0], state[2][1], state[2][2], state[2][3] = \
    state[2][2], state[2][3], state[2][0], state[2][1]

    # Row 3: [3,0] [3,1] [3,2] [3,3] -> [3,1] [3,2] [3,3] [3,0]
    state[3][0], state[3][1], state[3][2], state[3][3] = \
    state[3][1], state[3][2], state[3][3], state[3][0]

def _mix_columns(state: State) -> None:
    """
    Performs the MixColumns operation using GF(2^8) multiplication.
    Each column is multiplied by a fixed matrix:
    [2 3 1 1]
    [1 2 3 1]
    [1 1 2 3]
    [3 1 1 2]
    """
    for c in range(4):
        # Store original column values
        s0 = state[0][c]
        s1 = state[1][c]
        s2 = state[2][c]
        s3 = state[3][c]
        
        # New column values
        state[0][c] = gmul(s0, 2) ^ gmul(s1, 3) ^ gmul(s2, 1) ^ gmul(s3, 1)
        state[1][c] = gmul(s0, 1) ^ gmul(s1, 2) ^ gmul(s2, 3) ^ gmul(s3, 1)
        state[2][c] = gmul(s0, 1) ^ gmul(s1, 1) ^ gmul(s2, 2) ^ gmul(s3, 3)
        state[3][c] = gmul(s0, 3) ^ gmul(s1, 1) ^ gmul(s2, 1) ^ gmul(s3, 2)

def _inv_mix_columns(state: State) -> None:
    """
    Inverse of MixColumns.
    Each column is multiplied by the inverse matrix:
    [0x0E 0x0B 0x0D 0x09]
    [0x09 0x0E 0x0B 0x0D]
    [0x0D 0x09 0x0E 0x0B]
    [0x0B 0x0D 0x09 0x0E]
    """
    for c in range(4):
        s0 = state[0][c]
        s1 = state[1][c]
        s2 = state[2][c]
        s3 = state[3][c]

        state[0][c] = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09)
        state[1][c] = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d)
        state[2][c] = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b)
        state[3][c] = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e)

def _add_round_key(state: State, round_key: list[int]) -> None:
    """
    Adds (XORs) the round key to the state.
    The round key is a 1D list of 16 bytes, applied column by column.
    """
    for c in range(4):
        for r in range(4):
            # round_key[c*4 + r] selects the key byte
            state[r][c] ^= round_key[c*4 + r]

def _key_expansion(key: bytes) -> list[list[int]]:
    """
    Expands the initial key into a schedule of round keys.
    Returns a list of 16-byte round keys.
    """
    key_len = len(key)
    if key_len not in [16, 24, 32]:
        raise ValueError("Invalid key length: must be 16, 24, or 32 bytes")

    # Nk = key length in 32-bit words (4, 6, or 8)
    Nk = key_len // 4
    # Nr = number of rounds (10, 12, or 14)
    Nr = 10 + (Nk - 4) * 2
    
    # Nb = block size in 32-bit words (always 4 for AES)
    Nb = 4

    # The expanded key schedule, as a list of 32-bit words
    # Total words = Nb * (Nr + 1)
    w = [0] * (Nb * (Nr + 1))
    
    # First Nk words are just the key itself
    for i in range(Nk):
        w[i] = int.from_bytes(key[i*4 : i*4 + 4], 'big')

    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i-1]
        if i % Nk == 0:
            # Rotate, SubBytes, and Rcon XOR
            temp = ((temp << 8) & 0xFFFFFF00) | ((temp >> 24) & 0x000000FF) # RotWord
            
            # SubWord (apply S-box to each byte)
            temp_sub = 0
            temp_sub |= (S_BOX[(temp >> 24) & 0xFF]) << 24
            temp_sub |= (S_BOX[(temp >> 16) & 0xFF]) << 16
            temp_sub |= (S_BOX[(temp >> 8)  & 0xFF]) << 8
            temp_sub |= (S_BOX[ temp        & 0xFF])
            
            temp = temp_sub
            
            temp ^= (RCON[i // Nk] << 24)
            
        elif Nk > 6 and (i % Nk == 4):
            # Extra SubWord step for 256-bit keys
            temp_sub = 0
            temp_sub |= (S_BOX[(temp >> 24) & 0xFF]) << 24
            temp_sub |= (S_BOX[(temp >> 16) & 0xFF]) << 16
            temp_sub |= (S_BOX[(temp >> 8)  & 0xFF]) << 8
            temp_sub |= (S_BOX[ temp        & 0xFF])
            temp = temp_sub
        
        w[i] = w[i - Nk] ^ temp

    # Group the 32-bit words back into 16-byte round keys
    round_keys = []
    for i in range(Nr + 1):
        round_key = []
        for j in range(4):
            word = w[i*4 + j]
            round_key.extend(word.to_bytes(4, 'big'))
        round_keys.append(round_key)
        
    return round_keys

def _bytes_to_state(data: bytes) -> State:
    """Converts a 16-byte block into a 4x4 state (column-major)."""
    state = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = data[c*4 + r]
    return state

def _state_to_bytes(state: State) -> bytes:
    """Converts a 4x4 state back into a 16-byte block (column-major)."""
    return bytes(state[r][c] for c in range(4) for r in range(4))

def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypts a single 16-byte block."""
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")
        
    round_keys = _key_expansion(key)
    Nr = len(round_keys) - 1 # Number of rounds

    state = _bytes_to_state(block)

    # Initial AddRoundKey
    _add_round_key(state, round_keys[0])

    # Main rounds
    for i in range(1, Nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[i])

    # Final round (no MixColumns)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[Nr])

    return _state_to_bytes(state)

def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypts a single 16-byte block."""
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")
        
    round_keys = _key_expansion(key)
    Nr = len(round_keys) - 1

    state = _bytes_to_state(block)

    # Initial AddRoundKey (with last round key)
    _add_round_key(state, round_keys[Nr])

    # Main rounds (in reverse)
    for i in range(Nr - 1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[i])
        _inv_mix_columns(state)

    # Final round (no InvMixColumns)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)
