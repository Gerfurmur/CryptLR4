from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


block_size = 16
mac_pad = 128


def byte_xor(bytearray1, bytearray2):
    """
    xor of two bytearrays with equal length
    """
    return bytes([byte1 ^ byte2 for byte1, byte2 in zip(bytearray1, bytearray2)])


def pad(data, padding):
    """
    :param data: encrypting data - bytes
    :param padding: supplementation in form PKCS5
    :return: supplemented data - bytes
    """
    global block_size
    if padding == "PKCS5":
        p = bytes(block_size - len(data) for i in range(block_size - len(data)))
        return data + p
    if padding == "MAC_padding":
        p = (mac_pad).to_bytes(length=(block_size - len(data)), byteorder="little")
        return data + p
    raise ValueError("padding: expected PKCS5 or MAC_padding, but got {}".format(padding))




def aes_block_encrypt(key, data, is_final_block, padding="PKCS5"):
    """
    Function encrypts one 16 bytes length block using AES encryption with ECB mode
    :param key: a key, that used for encryption - bytes
    :param data: encrypting data - bytes
    :param is_final_block: flag
    :param padding: supplementation in form PKCS5
    :return: encrypted data block - bytes
    """
    pad_data = data
    if is_final_block:
        pad_data = pad(data, padding)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad_data)

