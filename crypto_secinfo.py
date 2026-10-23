import ctypes
from ctypes import wintypes, byref, c_void_p, create_string_buffer


adv = ctypes.WinDLL("advapi32", use_last_error=True)

# ---- константы CryptoAPI ----
PROV_RSA_FULL       = 1
CRYPT_VERIFYCONTEXT = 0xF0000000
CALG_MD5            = 0x8003      # хеш MD5
CALG_RC4            = 0x6801      # потоковый шифр RC4
CRYPT_CREATE_SALT   = 4           # «добавить к ключу случайное значение»
KP_SALT             = 2

KEY_BITS = 128   # если salt получится пустым, поставьте 40

# ---- описание типов функций (нужно для 64-битного Python) ----
adv.CryptAcquireContextW.argtypes = [c_void_p, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                     wintypes.DWORD, wintypes.DWORD]
adv.CryptCreateHash.argtypes  = [c_void_p, wintypes.UINT, c_void_p, wintypes.DWORD, c_void_p]
adv.CryptHashData.argtypes    = [c_void_p, c_void_p, wintypes.DWORD, wintypes.DWORD]
adv.CryptDeriveKey.argtypes   = [c_void_p, wintypes.UINT, c_void_p, wintypes.DWORD, c_void_p]
adv.CryptEncrypt.argtypes     = [c_void_p, c_void_p, wintypes.BOOL, wintypes.DWORD,
                                 c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
adv.CryptDecrypt.argtypes     = [c_void_p, c_void_p, wintypes.BOOL, wintypes.DWORD,
                                 c_void_p, ctypes.POINTER(wintypes.DWORD)]
adv.CryptGetKeyParam.argtypes = [c_void_p, wintypes.DWORD, c_void_p,
                                 ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
adv.CryptSetKeyParam.argtypes = [c_void_p, wintypes.DWORD, c_void_p, wintypes.DWORD]
adv.CryptDestroyKey.argtypes  = [c_void_p]
adv.CryptDestroyHash.argtypes = [c_void_p]
adv.CryptReleaseContext.argtypes = [c_void_p, wintypes.DWORD]


def _check(ok):
    """Если функция Windows вернула ошибку, выбросить исключение."""
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def _make_key(passphrase, salt=None):
    """Парольная фраза -> MD5 -> ключ RC4.
    salt=None: шифрование, генерируем новый salt.
    salt=bytes: расшифрование, подставляем salt из файла."""
    prov, h, key = c_void_p(), c_void_p(), c_void_p()

    # 1. подключаемся к криптопровайдеру
    _check(adv.CryptAcquireContextW(byref(prov), None, None,
                                    PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    # 2. создаём хеш-объект MD5 и «скармливаем» ему фразу
    _check(adv.CryptCreateHash(prov, CALG_MD5, None, 0, byref(h)))
    data = passphrase.encode("utf-8")
    _check(adv.CryptHashData(h, data, len(data), 0))

    # 3. из хеша делаем ключ RC4 (старшие 16 бит флагов = длина ключа)
    flags = (KEY_BITS << 16) | (CRYPT_CREATE_SALT if salt is None else 0)
    _check(adv.CryptDeriveKey(prov, CALG_RC4, h, flags, byref(key)))
    adv.CryptDestroyHash(h)

    # 4. работа с salt
    if salt is None:                          # шифруем: забираем созданный salt
        n = wintypes.DWORD(64)
        buf = create_string_buffer(64)
        _check(adv.CryptGetKeyParam(key, KP_SALT, buf, byref(n), 0))
        salt = buf.raw[:n.value]
    elif len(salt) > 0:                       # расшифровываем: возвращаем salt в ключ
        buf = create_string_buffer(salt, len(salt))
        _check(adv.CryptSetKeyParam(key, KP_SALT, buf, 0))
    return prov, key, salt


def encrypt_to_file(path, plaintext, passphrase):
    """Зашифровать bytes и записать в файл: [длина salt][salt][шифротекст]."""
    prov, key, salt = _make_key(passphrase)
    size = max(len(plaintext), 1)
    buf = create_string_buffer(plaintext, size)
    n = wintypes.DWORD(len(plaintext))
    _check(adv.CryptEncrypt(key, None, True, 0, buf, byref(n), size))
    with open(path, "wb") as f:
        f.write(bytes([len(salt)]) + salt + buf.raw[:n.value])
    adv.CryptDestroyKey(key)
    adv.CryptReleaseContext(prov, 0)


def decrypt_from_file(path, passphrase):
    """Прочитать файл, расшифровать, вернуть bytes (в памяти, не на диске)."""
    with open(path, "rb") as f:
        raw = f.read()
    slen = raw[0]
    salt, cipher = raw[1:1 + slen], raw[1 + slen:]
    prov, key, _ = _make_key(passphrase, salt)
    size = max(len(cipher), 1)
    buf = create_string_buffer(cipher, size)
    n = wintypes.DWORD(len(cipher))
    _check(adv.CryptDecrypt(key, None, True, 0, buf, byref(n)))
    adv.CryptDestroyKey(key)
    adv.CryptReleaseContext(prov, 0)
    return buf.raw[:n.value]