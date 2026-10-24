"""WPA2-CCMP EAPOL MIC verification with a strict JSON interchange format.

Generated exchanges are synthetic; imported message-2 data must be authorized.
Neither a successful MIC nor generated data proves a live router connection.
"""
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

METHOD = 'WPA2 PMK: PBKDF2-HMAC-SHA1 / 4096 / 32 bytes; PRF-512 PTK; EAPOL MIC HMAC-SHA1-128 (descriptor v2)'


def valid_ssid(value: str) -> str:
    if not 1 <= len(value.encode('utf-8')) <= 32:
        raise ValueError('SSID must contain 1–32 UTF-8 bytes')
    return value


def valid_password(value: str) -> str:
    if not 8 <= len(value) <= 63 or any(not 32 <= ord(c) <= 126 for c in value):
        raise ValueError('Use a WPA2 passphrase of 8–63 printable ASCII characters')
    return value


def pmk(password: str, ssid: str) -> bytes:
    return hashlib.pbkdf2_hmac('sha1', valid_password(password).encode('ascii'),
                               valid_ssid(ssid).encode('utf-8'), 4096, 32)


class LabData(BaseModel):
    model_config = ConfigDict(extra='forbid')
    format: str = Field(pattern=r'^wpa2lab-eapol-v1$')
    ssid: str
    ap_mac: str = Field(pattern=r'^[0-9a-f]{12}$')
    station_mac: str = Field(pattern=r'^[0-9a-f]{12}$')
    anonce: str = Field(pattern=r'^[0-9a-f]{64}$')
    snonce: str = Field(pattern=r'^[0-9a-f]{64}$')
    eapol: str = Field(min_length=198, max_length=8192, pattern=r'^(?:[0-9a-f]{2})+$')
    mic: str = Field(pattern=r'^[0-9a-f]{32}$')

    _ssid = field_validator('ssid')(valid_ssid)

    @model_validator(mode='after')
    def validate_packet(self):
        packet = bytes.fromhex(self.eapol)
        info = int.from_bytes(packet[5:7], 'big')
        if packet[0] not in (1, 2) or packet[1] != 3 or packet[4] != 2:
            raise ValueError('Only RSN EAPOL-Key message 2 (descriptor version 2) is supported')
        if int.from_bytes(packet[2:4], 'big') != len(packet) - 4:
            raise ValueError('EAPOL payload length mismatch')
        # Pairwise, MIC present, no ACK/install/request/error/encrypted-data bits.
        if info != 0x010a or int.from_bytes(packet[7:9], 'big') not in (0, 16):
            raise ValueError('Only pairwise CCMP message 2 / HMAC-SHA1 MIC is supported')
        if packet[17:49].hex() != self.snonce or packet[81:97] != bytes(16):
            raise ValueError('Message 2 must contain SNonce and a zeroed MIC field; supply MIC separately')
        if int.from_bytes(packet[97:99], 'big') != len(packet) - 99:
            raise ValueError('EAPOL key-data length mismatch')
        if self.ap_mac == self.station_mac or self.anonce == self.snonce:
            raise ValueError('Distinct MAC addresses and nonces are required')
        for mac in (self.ap_mac, self.station_mac):
            if bytes.fromhex(mac)[0] & 1 or int(mac, 16) == 0:
                raise ValueError('Unicast nonzero MAC addresses are required')
        return self


def digest(key: bytes, payload: bytes, independent=False) -> bytes:
    if independent:
        from cryptography.hazmat.primitives import hmac as audited_hmac
        value = audited_hmac.HMAC(key, hashes.SHA1())
        value.update(payload)
        return value.finalize()
    return hmac.new(key, payload, hashlib.sha1).digest()


def packet_mic(key: bytes, ap: str, station: str, anonce: str, snonce: str,
               packet: bytes, independent=False) -> str:
    macs = sorted([bytes.fromhex(ap), bytes.fromhex(station)])
    nonces = sorted([bytes.fromhex(anonce), bytes.fromhex(snonce)])
    context = b''.join(macs + nonces)
    ptk = b''.join(digest(key, b'Pairwise key expansion\x00' + context + bytes([i]), independent)
                   for i in range(4))[:64]
    return digest(ptk[:16], packet, independent)[:16].hex()


def generate(ssid: str, password: str) -> LabData:
    key = pmk(password, ssid)
    ap, station = '020000000001', '020000000002'
    anonce, snonce = secrets.token_hex(32), secrets.token_hex(32)
    # RSN information element: CCMP group/pairwise cipher and PSK AKM.
    rsn = bytes.fromhex('30140100000fac040100000fac040100000fac020000')
    packet = bytearray(99 + len(rsn))
    packet[:9] = b'\x02\x03' + (len(packet) - 4).to_bytes(2, 'big') + bytes.fromhex('02010a0010')
    packet[9:17] = (1).to_bytes(8, 'big')
    packet[17:49] = bytes.fromhex(snonce)
    packet[97:99] = len(rsn).to_bytes(2, 'big')
    packet[99:] = rsn
    mic = packet_mic(key, ap, station, anonce, snonce, packet)
    return LabData(format='wpa2lab-eapol-v1', ssid=ssid, ap_mac=ap, station_mac=station,
                   anonce=anonce, snonce=snonce, eapol=packet.hex(), mic=mic)


def verify(data: LabData, candidate: str, independent: bool = False) -> bool:
    try:
        valid_password(candidate)
    except ValueError:
        return False
    if independent:
        key = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32,
                        salt=data.ssid.encode('utf-8'), iterations=4096).derive(candidate.encode('ascii'))
    else:
        key = pmk(candidate, data.ssid)
    actual = packet_mic(key, data.ap_mac, data.station_mac, data.anonce, data.snonce,
                        bytes.fromhex(data.eapol), independent)
    return hmac.compare_digest(actual, data.mic)


def password_advice(password: str) -> dict:
    valid_password(password)
    warnings = []
    if len(password) < 16:
        warnings.append('Prefer at least 16 randomly generated characters.')
    if password.lower() in {'password', 'password123', '12345678', 'qwerty123', '123456789'}:
        warnings.append('Common password: replace it.')
    if len(set(password)) < 5:
        warnings.append('Very repetitive password.')
    return {'length': len(password), 'warnings': warnings,
            'note': 'Heuristic advice only; no entropy score or guaranteed resistance.'}
