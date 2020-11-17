import aes


R128 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x87"
bytesize = 8
base = 2
table = {0: 255, 1: 128, 2: 192, 3: 224, 4: 240, 5: 248, 6: 252, 7: 254}


def okr(num):
    """
    num: округляемое число
    :return: минимальное челое число >= num/8
    """
    global bytesize
    if num/bytesize > num//bytesize:
        return num//bytesize + 1
    return num//bytesize


def msb(data, length):
    global bytesize
    result = b""
    for i in range(okr(length)):
        it = data[i]
        if i == okr(length) - 1:
            it &= table[length % bytesize]
        result += it.to_bytes(1, byteorder="big")
    return result


def bytes_left_shift(data, shift):
    global bytesize, base
    bits = ""
    res = b""
    for byte in range(len(data)):
        bits += format(data[byte], "b").rjust(bytesize, "0")
    bits = bits[shift:].ljust(len(data)*bytesize, "0")
    for i in range(len(data)):
        res += int(bits[i*bytesize:(i+1)*bytesize], base).to_bytes(length=1, byteorder="big")
    return res


class OMAC:
    blocksize = 16
    tlen = 128
    padding = "MAC_padding"

    def __init__(self, key=None, data=None):
        """
        Создание нового объекта HMAC, который использует SHA256.
        key: массив байт, ключ.
        msg: массив байт, данные.
        """
        self.key = key
        self.key1 = None
        self.key2 = None
        self.is_final_block = False
        self.blocks = []
        if key is not None:
            self.set_key(key)
            if data is not None:
                self.compute_mac(data)

    def set_key(self, key):
        """
        Инициализирует объект HMAC ключом key
        :param key: bytes
        """
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key: expected bytes or bytearray, but got {}".format(type(key).__name__))
        elif len(key) != OMAC.blocksize:
            raise ValueError("key: expected length 16 bytes, but got {}".format(len(key)))
        self.key = key
        L = aes.aes_block_encrypt(key, bytes(OMAC.blocksize), False)
        if format(L[0], "b")[0] == 0:
            key1 = bytes_left_shift(L, 1)
        else:
            key1 = aes.byte_xor(bytes_left_shift(L, 1), R128)
        if format(key1[0], "b")[0] == 0:
            key2 = bytes_left_shift(key1, 1)
        else:
            key2 = aes.byte_xor(bytes_left_shift(key1, 1), R128)
        self.key1 = key1
        self.key2 = key2

    def mac_add_block(self, data):
        """Наполнение данными из msg в наш хешируемый объект."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data: expected bytes or bytearray, but got {}".format(type(data).__name__))
        elif len(data) > OMAC.blocksize:
            raise ValueError("data: expected length 16 bytes, but got {}".format(len(data)))
        if not self.is_final_block:
            self.blocks.append(data)
        if len(data) < OMAC.blocksize:
            self.is_final_block = True

    def mac_finalize(self):
        """
        Возврат значения хеша
        :return: bytes
        """
        previous = bytes(OMAC.blocksize)
        if len(self.blocks[-1]) < OMAC.blocksize:
            self.blocks[-1] = aes.byte_xor(aes.pad(self.blocks[-1], OMAC.padding), self.key2)
        else:
            self.blocks[-1] = aes.byte_xor(self.blocks[-1], self.key1)
        self.is_final_block = False
        for block in self.blocks:
            previous = aes.aes_block_encrypt(self.key, aes.byte_xor(previous, block), self.is_final_block, OMAC.padding)
        self.blocks = []
        return msb(previous, OMAC.tlen)

    def compute_mac(self, data):
        """
        Вычисляет код аутентичности для прозвольных
        данных, используя метод mac_add_block
        data - данные в байтах
        :param data: bytes
        :return: bytes
        """
        if len(data) == 0:
            return None
        blocks_number = len(data) // OMAC.blocksize
        for block_num in range(blocks_number):
            self.mac_add_block(data[OMAC.blocksize * block_num:OMAC.blocksize * (block_num + 1)])
        if blocks_number < len(data) / OMAC.blocksize:
            self.mac_add_block(data[OMAC.blocksize * blocks_number:])
        return self.mac_finalize()

    def verify_mac(self, data, tag):
        """
        Проверяет код аутентичности для прозвольных данных,
        используя метод compute_mac
        :param data: bytes
        :param tag: bytes
        :return: boolean
        """
        if not isinstance(tag, (bytes, bytearray)):
            raise TypeError("tag: expected bytes or bytearray, but got {}".format(type(tag).__name__))
        if len(tag) != okr(OMAC.tlen):
            raise ValueError("tag: expected length {} bytes, but got {}".format(okr(OMAC.tlen), len(tag)))
        if self.compute_mac(data) == tag:
            return True
        return False
