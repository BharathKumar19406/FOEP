# src/foep/normalize/hash_utils.py

import hashlib
from typing import Union


def compute_sha256(data: Union[bytes, str]) -> str:
    """
    Compute SHA-256 hash of input data.

    Args:
         Bytes or string to hash. Strings are encoded as UTF-8.

    Returns:
        Hexadecimal SHA-256 hash string (64 lowercase chars).

    Examples:
        >>> compute_sha256(b"hello")
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'

        >>> compute_sha256("hello")
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif not isinstance(data, bytes):
        raise TypeError("Input must be bytes or str")

    return hashlib.sha256(data).hexdigest()


def compute_sha256_from_file(file_path: str, chunk_size: int = 65536) -> str:
    """
    Compute SHA-256 hash of a file incrementally (memory-efficient).

    Args:
        file_path: Path to file
        chunk_size: Bytes to read at a time (default: 64KB)

    Returns:
        Hexadecimal SHA-256 hash string.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()
