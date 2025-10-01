import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from safer_ed import encrypt, decrypt 

def test_encrypt_decrypt():
    msg = "Привет, мир!"
    key = "123456"

    encrypted = encrypt(msg, key)
    decrypted = decrypt(encrypted, key)

    assert decrypted == msg
