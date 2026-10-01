import ctypes

from agent.security_data import PROTECTED_DACL_SECURITY_INFORMATION


def test_protected_security_info_fits_signed_win32_long_without_losing_bits():
    info = PROTECTED_DACL_SECURITY_INFORMATION | 0x1 | 0x4
    assert -(1 << 31) <= info <= (1 << 31) - 1
    assert ctypes.c_uint32(info).value == 0x80000005
