"""Read the Windows PnP topology used to group USB interface nodes."""

from __future__ import annotations

import ctypes
import logging
import sys
import uuid
from ctypes import wintypes
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PnpProperties:
    parent: str | None = None
    container_id: str | None = None
    bus_description: str | None = None
    removal_policy: int | None = None


if sys.platform == 'win32':
    ULONG_PTR = wintypes.WPARAM

    class GUID(ctypes.Structure):
        _fields_ = [
            ('Data1', wintypes.DWORD),
            ('Data2', wintypes.WORD),
            ('Data3', wintypes.WORD),
            ('Data4', ctypes.c_ubyte * 8),
        ]

    class SP_DEVINFO_DATA(ctypes.Structure):
        _fields_ = [
            ('cbSize', wintypes.DWORD),
            ('ClassGuid', GUID),
            ('DevInst', wintypes.DWORD),
            ('Reserved', ULONG_PTR),
        ]

    class DEVPROPKEY(ctypes.Structure):
        _fields_ = [('fmtid', GUID), ('pid', wintypes.DWORD)]


def _guid(value: str) -> 'GUID':
    parsed = uuid.UUID(value)
    fields = parsed.fields
    return GUID(fields[0], fields[1], fields[2], (ctypes.c_ubyte * 8)(*parsed.bytes[8:]))


def _property_key(fmtid: str, pid: int) -> 'DEVPROPKEY':
    return DEVPROPKEY(_guid(fmtid), pid)


def _guid_text(value: 'GUID') -> str:
    raw = bytes(value.Data4)
    parsed = uuid.UUID(fields=(
        value.Data1,
        value.Data2,
        value.Data3,
        raw[0],
        raw[1],
        int.from_bytes(raw[2:], 'big'),
    ))
    return '{' + str(parsed).upper() + '}'


def enumerate_pnp_properties() -> dict[str, PnpProperties]:
    """Return parent/container/bus-name properties for every present PnP node."""
    if sys.platform != 'win32':
        return {}

    setupapi = ctypes.WinDLL('setupapi', use_last_error=True)
    setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE
    setupapi.SetupDiGetClassDevsW.argtypes = [
        ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.HWND, wintypes.DWORD,
    ]
    setupapi.SetupDiEnumDeviceInfo.restype = wintypes.BOOL
    setupapi.SetupDiEnumDeviceInfo.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(SP_DEVINFO_DATA),
    ]
    setupapi.SetupDiGetDeviceInstanceIdW.restype = wintypes.BOOL
    setupapi.SetupDiGetDeviceInstanceIdW.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(SP_DEVINFO_DATA), wintypes.LPWSTR,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    setupapi.SetupDiGetDevicePropertyW.restype = wintypes.BOOL
    setupapi.SetupDiGetDevicePropertyW.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(SP_DEVINFO_DATA), ctypes.POINTER(DEVPROPKEY),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
    ]
    setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]

    digcf_present = 0x00000002
    digcf_allclasses = 0x00000004
    invalid_handle = ctypes.c_void_p(-1).value
    handle = setupapi.SetupDiGetClassDevsW(
        None, None, None, digcf_present | digcf_allclasses,
    )
    if handle == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())

    parent_key = _property_key('4340A6C5-93FA-4706-972C-7B648008A5A7', 8)
    container_key = _property_key('8C7ED206-3F8A-4827-B3AB-AE9E1FAEFC6C', 2)
    bus_desc_key = _property_key('540B947E-8B40-45BC-A8A2-6A0B894CBDA2', 4)
    removal_policy_key = _property_key('A45C254E-DF1C-4EFD-8020-67D146A850E0', 33)

    result: dict[str, PnpProperties] = {}
    try:
        index = 0
        while True:
            info = SP_DEVINFO_DATA()
            info.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
            if not setupapi.SetupDiEnumDeviceInfo(handle, index, ctypes.byref(info)):
                if ctypes.get_last_error() == 259:  # ERROR_NO_MORE_ITEMS
                    break
                raise ctypes.WinError(ctypes.get_last_error())
            index += 1

            instance_buffer = ctypes.create_unicode_buffer(2048)
            if not setupapi.SetupDiGetDeviceInstanceIdW(
                handle, ctypes.byref(info), instance_buffer,
                len(instance_buffer), None,
            ):
                continue

            instance_id = instance_buffer.value.upper()
            result[instance_id] = PnpProperties(
                parent=_read_string_property(setupapi, handle, info, parent_key),
                container_id=_read_guid_property(setupapi, handle, info, container_key),
                bus_description=_read_string_property(setupapi, handle, info, bus_desc_key),
                removal_policy=_read_uint32_property(
                    setupapi, handle, info, removal_policy_key,
                ),
            )
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(handle)

    return result


def _read_property_bytes(
    setupapi: object,
    handle: int,
    info: 'SP_DEVINFO_DATA',
    key: 'DEVPROPKEY',
) -> bytes | None:
    prop_type = wintypes.DWORD()
    required = wintypes.DWORD()
    setupapi.SetupDiGetDevicePropertyW(
        handle, ctypes.byref(info), ctypes.byref(key), ctypes.byref(prop_type),
        None, 0, ctypes.byref(required), 0,
    )
    if not required.value:
        return None

    buffer = (ctypes.c_ubyte * required.value)()
    if not setupapi.SetupDiGetDevicePropertyW(
        handle, ctypes.byref(info), ctypes.byref(key), ctypes.byref(prop_type),
        buffer, required.value, ctypes.byref(required), 0,
    ):
        return None
    return bytes(buffer[:required.value])


def _read_string_property(
    setupapi: object,
    handle: int,
    info: 'SP_DEVINFO_DATA',
    key: 'DEVPROPKEY',
) -> str | None:
    raw = _read_property_bytes(setupapi, handle, info, key)
    if not raw:
        return None
    return raw.decode('utf-16-le', errors='replace').rstrip('\x00') or None


def _read_guid_property(
    setupapi: object,
    handle: int,
    info: 'SP_DEVINFO_DATA',
    key: 'DEVPROPKEY',
) -> str | None:
    raw = _read_property_bytes(setupapi, handle, info, key)
    if not raw or len(raw) < ctypes.sizeof(GUID):
        return None
    value = GUID.from_buffer_copy(raw)
    return _guid_text(value)


def _read_uint32_property(
    setupapi: object,
    handle: int,
    info: 'SP_DEVINFO_DATA',
    key: 'DEVPROPKEY',
) -> int | None:
    raw = _read_property_bytes(setupapi, handle, info, key)
    if not raw or len(raw) < ctypes.sizeof(wintypes.DWORD):
        return None
    return wintypes.DWORD.from_buffer_copy(raw).value


def safe_enumerate_pnp_properties() -> dict[str, PnpProperties]:
    try:
        return enumerate_pnp_properties()
    except Exception as exc:
        logger.warning('Falha ao ler topologia PnP via SetupAPI: %s', exc)
        return {}
