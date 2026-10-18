"""Windows user-scoped DPAPI protection for vault blobs."""

import ctypes
import os
from ctypes import wintypes


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _transform(data: bytes, decrypt: bool) -> bytes:
    if os.name != "nt":
        raise RuntimeError("Questa alfa richiede Windows DPAPI")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    blob_ptr = ctypes.POINTER(_DataBlob)
    crypt32.CryptProtectData.argtypes = [blob_ptr, wintypes.LPCWSTR, blob_ptr, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, blob_ptr]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [blob_ptr, ctypes.c_void_p, blob_ptr, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, blob_ptr]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    buffer = ctypes.create_string_buffer(data or b"\0")
    incoming = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    outgoing = _DataBlob()
    if decrypt:
        success = crypt32.CryptUnprotectData(ctypes.byref(incoming), None, None, None, None, 0x1, ctypes.byref(outgoing))
    else:
        success = crypt32.CryptProtectData(ctypes.byref(incoming), "DataSovereign alpha", None, None, None, 0x1, ctypes.byref(outgoing))
    if not success:
        raise OSError(ctypes.get_last_error(), "Windows DPAPI operation failed")
    try:
        return ctypes.string_at(outgoing.pbData, outgoing.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(outgoing.pbData, ctypes.c_void_p))


def protect(data: bytes) -> bytes:
    return _transform(data, decrypt=False)


def unprotect(data: bytes) -> bytes:
    return _transform(data, decrypt=True)
