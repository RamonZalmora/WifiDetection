"""Read-only Windows Native WiFi API integration; no shell commands or capture."""
import ctypes as C
import platform
import time
import uuid
from ctypes import wintypes as W


class GUID(C.Structure):
    _fields_ = [('a', C.c_uint32), ('b', C.c_uint16), ('c', C.c_uint16), ('d', C.c_ubyte * 8)]


class SSID(C.Structure):
    _fields_ = [('length', C.c_uint32), ('data', C.c_ubyte * 32)]


class Interface(C.Structure):
    _fields_ = [('guid', GUID), ('description', C.c_wchar * 256), ('state', C.c_uint32)]


class Available(C.Structure):
    _fields_ = [('profile', C.c_wchar * 256), ('ssid', SSID), ('bss_type', C.c_uint32),
                ('bss_count', C.c_uint32), ('connectable', C.c_int32), ('reason', C.c_uint32),
                ('phy_count', C.c_uint32), ('phy_types', C.c_uint32 * 8),
                ('more_phy', C.c_int32), ('signal', C.c_uint32), ('security', C.c_int32),
                ('auth', C.c_uint32), ('cipher', C.c_uint32), ('flags', C.c_uint32),
                ('reserved', C.c_uint32)]


class Rates(C.Structure):
    _fields_ = [('length', C.c_uint32), ('rates', C.c_uint16 * 126)]


class BSS(C.Structure):
    _fields_ = [('ssid', SSID), ('phy_id', C.c_uint32), ('mac', C.c_ubyte * 6),
                ('bss_type', C.c_uint32), ('phy_type', C.c_uint32), ('rssi', C.c_int32),
                ('quality', C.c_uint32), ('reg_domain', C.c_ubyte),
                ('beacon_period', C.c_uint16), ('timestamp', C.c_uint64),
                ('host_timestamp', C.c_uint64), ('capabilities', C.c_uint16),
                ('frequency', C.c_uint32), ('rates', Rates),
                ('ie_offset', C.c_uint32), ('ie_size', C.c_uint32)]


class BSSHeader(C.Structure):
    _fields_ = [('total', C.c_uint32), ('count', C.c_uint32), ('first', BSS)]


AUTH = {1: 'Open', 2: 'Shared key', 3: 'WPA-Enterprise', 4: 'WPA-Personal',
        5: 'WPA-None', 6: 'WPA2-Enterprise', 7: 'WPA2-Personal', 8: 'WPA3',
        9: 'WPA3-Personal', 10: 'OWE', 11: 'WPA3-Enterprise'}
CIPHER = {0: 'None', 1: 'WEP40', 2: 'TKIP', 4: 'CCMP', 5: 'WEP104',
          8: 'GCMP', 9: 'GCMP-256', 10: 'CCMP-256', 0x101: 'WEP'}
PHY = {1: 'FHSS', 2: 'DSSS', 4: '802.11a', 5: '802.11b', 6: '802.11g',
       7: '802.11n', 8: '802.11ac', 10: '802.11ax', 11: '802.11be'}
STATE = {0: 'not ready', 1: 'connected', 2: 'ad hoc', 3: 'disconnecting',
         4: 'disconnected', 5: 'associating', 6: 'discovering', 7: 'authenticating'}


def channel(khz: int):
    mhz = khz // 1000
    if mhz == 2484:
        return '2.4 GHz', 14
    if 2412 <= mhz <= 2472:
        return '2.4 GHz', (mhz - 2407) // 5
    if 5955 <= mhz <= 7115:
        return '6 GHz', (mhz - 5950) // 5
    if 5000 <= mhz < 5925:
        return '5 GHz', (mhz - 5000) // 5
    return 'Unknown', None


def ssid_text(ssid):
    return bytes(ssid.data[:min(ssid.length, 32)]).decode('utf-8', errors='replace')


def assessment(network):
    risks = []
    if network.get('authentication') in ('Open', 'Shared key', 'WPA-Personal', 'WPA-Enterprise'):
        risks.append('Open or legacy authentication observed; prefer WPA3 or WPA2-AES.')
    if network.get('encryption') in ('None', 'WEP', 'WEP40', 'WEP104', 'TKIP'):
        risks.append('Absent or legacy encryption observed.')
    return {'observed_risks': risks, 'wps': 'Not determined', 'firmware': 'Not determined',
            'guidance': ['Check WPS in your router settings and disable it when unnecessary.',
                         'Use current vendor firmware and a unique random passphrase.',
                         'Scanning cannot reveal a password or establish monitor-mode support.']}


class NativeWifi:
    def scan(self):
        if platform.system() != 'Windows':
            return {'status': 'unsupported', 'timestamp': time.time(), 'adapters': [], 'networks': [],
                    'errors': ['Native scanning requires Windows 11 and a wireless adapter. No simulated results.']}
        try:
            return self._windows()
        except (OSError, RuntimeError) as exc:
            return {'status': 'error', 'timestamp': time.time(), 'adapters': [], 'networks': [],
                    'errors': [str(exc)]}

    def _windows(self):
        dll = C.WinDLL('wlanapi.dll')
        ptr = C.c_void_p
        signatures = {
            'WlanOpenHandle': ([W.DWORD, ptr, C.POINTER(W.DWORD), C.POINTER(ptr)], W.DWORD),
            'WlanCloseHandle': ([ptr, ptr], W.DWORD),
            'WlanEnumInterfaces': ([ptr, ptr, C.POINTER(ptr)], W.DWORD),
            'WlanScan': ([ptr, C.POINTER(GUID), ptr, ptr, ptr], W.DWORD),
            'WlanGetAvailableNetworkList': ([ptr, C.POINTER(GUID), W.DWORD, ptr, C.POINTER(ptr)], W.DWORD),
            'WlanGetNetworkBssList': ([ptr, C.POINTER(GUID), ptr, W.DWORD, W.BOOL, ptr, C.POINTER(ptr)], W.DWORD),
            'WlanQueryInterface': ([ptr, C.POINTER(GUID), W.DWORD, ptr, C.POINTER(W.DWORD), C.POINTER(ptr), ptr], W.DWORD),
            'WlanGetInterfaceCapability': ([ptr, C.POINTER(GUID), ptr, C.POINTER(ptr)], W.DWORD),
            'WlanFreeMemory': ([ptr], None),
        }
        for name, (args, result) in signatures.items():
            function = getattr(dll, name)
            function.argtypes, function.restype = args, result

        def check(code):
            if code:
                hint = (' Enable Windows Location services and allow desktop apps location access; '
                        'check WLAN AutoConfig and the adapter driver.' if code == 5 else
                        ' Check WLAN AutoConfig, radio state, and the adapter driver.')
                raise RuntimeError(f'Windows WLAN error {code}.{hint}')

        def allocated(function, *args):
            value = ptr()
            check(function(*args, C.byref(value)))
            return value

        handle, version = ptr(), W.DWORD()
        check(dll.WlanOpenHandle(2, None, C.byref(version), C.byref(handle)))
        adapters, networks, errors = [], [], []
        try:
            interfaces = allocated(dll.WlanEnumInterfaces, handle, None)
            try:
                count = C.cast(interfaces, C.POINTER(C.c_uint32))[0]
                if count > 64:
                    raise RuntimeError('Unexpected interface count')
                items = (Interface * count).from_address(interfaces.value + 8)
                for item in items:
                    adapter = {'name': item.description, 'state': STATE.get(item.state, 'unknown'),
                               'manufacturer': 'Not exposed by this API', 'driver': 'Not exposed by this API',
                               'standards': [], 'native_scan': False, 'monitor_mode': 'Not determined'}
                    adapters.append(adapter)
                    adapter.update(driver_metadata(item.guid))
                    caps = ptr()
                    code = dll.WlanGetInterfaceCapability(handle, C.byref(item.guid), None, C.byref(caps))
                    if not code:
                        try:
                            words = C.cast(caps, C.POINTER(C.c_uint32))
                            n = min(words[4], 64)
                            adapter['standards'] = [PHY.get(words[5+i], f'PHY {words[5+i]}') for i in range(n)]
                        finally:
                            dll.WlanFreeMemory(caps)
                    try:
                        check(dll.WlanScan(handle, C.byref(item.guid), None, None, None))
                        # Native scans are asynchronous. Return Windows' cached observations
                        # explicitly; never label the request time as observation freshness.
                        adapter['native_scan'] = True
                        available = allocated(dll.WlanGetAvailableNetworkList, handle, C.byref(item.guid), 0, None)
                        security = {}
                        try:
                            n = C.cast(available, C.POINTER(C.c_uint32))[0]
                            if n > 4096:
                                raise RuntimeError('Unexpected network count')
                            for net in (Available * n).from_address(available.value + 8):
                                key = (bytes(net.ssid.data[:min(net.ssid.length, 32)]), net.bss_type)
                                security.setdefault(key, set()).add((net.auth, net.cipher))
                        finally:
                            dll.WlanFreeMemory(available)
                        bsses = allocated(dll.WlanGetNetworkBssList, handle, C.byref(item.guid), None, 3, False, None)
                        try:
                            header = C.cast(bsses, C.POINTER(BSSHeader)).contents
                            offset = BSSHeader.first.offset
                            if header.count > 4096 or offset + header.count * C.sizeof(BSS) > header.total:
                                raise RuntimeError('Invalid BSS list size')
                            for bss in (BSS * header.count).from_address(bsses.value + offset):
                                key = (bytes(bss.ssid.data[:min(bss.ssid.length, 32)]), bss.bss_type)
                                options = security.get(key, set())
                                auth, cipher = next(iter(options)) if len(options) == 1 else (None, None)
                                band, chan = channel(bss.frequency)
                                row = {'ssid': ssid_text(bss.ssid), 'bssid': ':'.join(f'{b:02x}' for b in bss.mac),
                                       'signal': bss.quality, 'rssi_dbm': bss.rssi, 'band': band, 'channel': chan,
                                       'frequency_khz': bss.frequency, 'adapter': item.description,
                                       'connection_state': adapter['state'],
                                       'authentication': AUTH.get(auth, 'Unknown / ambiguous'),
                                       'encryption': CIPHER.get(cipher, 'Unknown / ambiguous'),
                                       'security_scope': 'SSID-level Windows classification; BSSID security not independently confirmed',
                                       'last_seen_windows_ticks': bss.host_timestamp}
                                row['analysis'] = assessment(row)
                                networks.append(row)
                        finally:
                            dll.WlanFreeMemory(bsses)
                    except RuntimeError as exc:
                        errors.append(f'{item.description}: {exc}')
            finally:
                dll.WlanFreeMemory(interfaces)
        finally:
            dll.WlanCloseHandle(handle, None)
        return {'status': 'partial' if errors else 'ok', 'timestamp': time.time(), 'adapters': adapters,
                'networks': networks, 'errors': errors,
                'freshness': 'Cached Windows observations; scan requested asynchronously. Refresh after a few seconds.'}


def driver_metadata(guid):
    """Read optional adapter metadata from the Windows network driver class."""
    import winreg
    result = {}
    identifier = str(uuid.UUID(bytes_le=bytes(guid))).lower()
    path = r'SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as root:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(root, name) as key:
                        actual = winreg.QueryValueEx(key, 'NetCfgInstanceId')[0].strip('{}').lower()
                        if actual != identifier:
                            continue
                        for source, target in [('DriverVersion', 'driver'), ('ProviderName', 'driver_provider'),
                                               ('Manufacturer', 'manufacturer')]:
                            try:
                                result[target] = winreg.QueryValueEx(key, source)[0]
                            except OSError:
                                pass
                        break
                except OSError:
                    continue
    except OSError:
        pass
    return result
