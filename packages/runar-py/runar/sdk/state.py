"""State serialization — encode/decode state values as Bitcoin Script push data."""

from __future__ import annotations
from runar.sdk.types import RunarArtifact, StateField


def serialize_state(fields: list[StateField], values: dict) -> str:
    """Encode state values into hex-encoded Bitcoin Script data section."""
    sorted_fields = sorted(fields, key=lambda f: f.index)
    hex_str = ''
    for field in sorted_fields:
        value = values.get(field.name)
        hex_str += _encode_state_value(value, field.type)
    return hex_str


def deserialize_state(fields: list[StateField], script_hex: str) -> dict:
    """Decode state values from a hex-encoded Bitcoin Script data section."""
    sorted_fields = sorted(fields, key=lambda f: f.index)
    result = {}
    offset = 0
    for field in sorted_fields:
        value, bytes_read = _decode_state_value(script_hex, offset, field.type)
        result[field.name] = value
        offset += bytes_read
    return result


def extract_state_from_script(artifact: RunarArtifact, script_hex: str) -> dict | None:
    """Extract state values from a full locking script hex."""
    if not artifact.state_fields:
        return None
    op_return_pos = find_last_op_return(script_hex)
    if op_return_pos == -1:
        return None
    state_hex = script_hex[op_return_pos + 2:]
    return deserialize_state(artifact.state_fields, state_hex)


def find_last_op_return(script_hex: str) -> int:
    """Find the last OP_RETURN (0x6a) at a real opcode boundary.

    Returns the hex-char offset, or -1 if not found.
    """
    last_pos = -1
    offset = 0
    length = len(script_hex)

    while offset + 2 <= length:
        opcode = int(script_hex[offset:offset + 2], 16)

        if opcode == 0x6A:
            last_pos = offset
            offset += 2
        elif 0x01 <= opcode <= 0x4B:
            offset += 2 + opcode * 2
        elif opcode == 0x4C:
            if offset + 4 > length:
                break
            push_len = int(script_hex[offset + 2:offset + 4], 16)
            offset += 4 + push_len * 2
        elif opcode == 0x4D:
            if offset + 6 > length:
                break
            lo = int(script_hex[offset + 2:offset + 4], 16)
            hi = int(script_hex[offset + 4:offset + 6], 16)
            push_len = lo | (hi << 8)
            offset += 6 + push_len * 2
        elif opcode == 0x4E:
            if offset + 10 > length:
                break
            b = bytes.fromhex(script_hex[offset + 2:offset + 10])
            push_len = int.from_bytes(b, 'little')
            offset += 10 + push_len * 2
        else:
            offset += 2

    return last_pos


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def encode_script_int(n: int) -> str:
    """Encode an integer as Bitcoin Script push data (for state serialization)."""
    if n == 0:
        return '00'  # OP_0

    negative = n < 0
    abs_val = abs(n)

    result_bytes = []
    while abs_val > 0:
        result_bytes.append(abs_val & 0xFF)
        abs_val >>= 8

    if result_bytes[-1] & 0x80:
        result_bytes.append(0x80 if negative else 0x00)
    elif negative:
        result_bytes[-1] |= 0x80

    data_hex = bytes(result_bytes).hex()
    return encode_push_data(data_hex)


def decode_script_int(hex_str: str) -> int:
    """Decode a minimally-encoded Bitcoin Script integer from hex."""
    if not hex_str or hex_str == '00':
        return 0

    b = bytes.fromhex(hex_str)
    negative = (b[-1] & 0x80) != 0
    data = bytearray(b)
    data[-1] &= 0x7F

    result = 0
    for i in range(len(data) - 1, -1, -1):
        result = (result << 8) | data[i]

    return -result if negative else result


def encode_push_data(data_hex: str) -> str:
    """Wrap hex data in a Bitcoin Script push data opcode."""
    data_len = len(data_hex) // 2

    if data_len <= 75:
        return f'{data_len:02x}' + data_hex
    elif data_len <= 0xFF:
        return '4c' + f'{data_len:02x}' + data_hex
    elif data_len <= 0xFFFF:
        return '4d' + data_len.to_bytes(2, 'little').hex() + data_hex
    else:
        return '4e' + data_len.to_bytes(4, 'little').hex() + data_hex


def decode_push_data(hex_str: str, offset: int) -> tuple[str, int]:
    """Decode a Bitcoin Script push data at the given hex offset.

    Returns (data_hex, hex_chars_consumed).
    """
    if offset >= len(hex_str):
        return '', 0

    opcode = int(hex_str[offset:offset + 2], 16)

    if opcode <= 75:
        data_len = opcode * 2
        return hex_str[offset + 2:offset + 2 + data_len], 2 + data_len
    elif opcode == 0x4C:
        length = int(hex_str[offset + 2:offset + 4], 16)
        data_len = length * 2
        return hex_str[offset + 4:offset + 4 + data_len], 4 + data_len
    elif opcode == 0x4D:
        lo = int(hex_str[offset + 2:offset + 4], 16)
        hi = int(hex_str[offset + 4:offset + 6], 16)
        length = lo | (hi << 8)
        data_len = length * 2
        return hex_str[offset + 6:offset + 6 + data_len], 6 + data_len
    elif opcode == 0x4E:
        b = bytes.fromhex(hex_str[offset + 2:offset + 10])
        length = int.from_bytes(b, 'little')
        data_len = length * 2
        return hex_str[offset + 10:offset + 10 + data_len], 10 + data_len

    return '', 2


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _encode_state_value(value, field_type: str) -> str:
    if field_type in ('int', 'bigint'):
        n = int(value) if value is not None else 0
        return encode_script_int(n)
    elif field_type == 'bool':
        return '51' if value else '00'
    else:
        hex_str = value if isinstance(value, str) else ''
        return encode_push_data(hex_str)


def _decode_state_value(hex_str: str, offset: int, field_type: str) -> tuple:
    if field_type == 'bool':
        if offset + 2 > len(hex_str):
            return False, 2
        opcode = hex_str[offset:offset + 2]
        return opcode == '51', 2
    elif field_type in ('int', 'bigint'):
        data, bytes_read = decode_push_data(hex_str, offset)
        return decode_script_int(data), bytes_read
    else:
        data, bytes_read = decode_push_data(hex_str, offset)
        return data, bytes_read
