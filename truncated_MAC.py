import aes


R128 = b"\x00\x00\x00\x00\x00\x00\x00\x87"
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



class t_MAC:
    blocksize = 16
    tlen = 64
    padding = "PKCS5"

    def __init__(self, key=None, data=None):
        """
        Создание нового объекта HMAC, который использует SHA256.
        key: массив байт, ключ.
        msg: массив байт, данные.
        """
        self.key = key
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
        elif len(key) != t_MAC.blocksize:
            raise ValueError("key: expected length 16 bytes, but got {}".format(len(key)))
        self.key = key

    def mac_add_block(self, data):
        """Наполнение данными из msg в наш хешируемый объект."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data: expected bytes or bytearray, but got {}".format(type(data).__name__))
        elif len(data) > t_MAC.blocksize:
            raise ValueError("data: expected length 16 bytes, but got {}".format(len(data)))
        if not self.is_final_block:
            self.blocks.append(data)
        if len(data) < t_MAC.blocksize:
            self.is_final_block = True

    def mac_finalize(self):
        """
        Возврат значения хеша
        :return: bytes
        """
        previous = bytes(t_MAC.blocksize)
        self.is_final_block = False
        for block in self.blocks[:-1]:
            previous = aes.aes_block_encrypt(self.key, aes.byte_xor(previous, block),
                                             self.is_final_block, t_MAC.padding)
        previous = aes.aes_block_encrypt(self.key, aes.byte_xor(previous, self.blocks[-1]),
                                         True, t_MAC.padding)
        self.blocks = []
        return previous

    def compute_mac(self, data):
        """
        Вычисляет код аутентичности для прозвольных
        данных, используя метод mac_add_block
        data - данные в байтах
        :param data: bytes
        :return: bytes
        """
        blocks_number = len(data) // t_MAC.blocksize
        for block_num in range(blocks_number):
            self.mac_add_block(data[t_MAC.blocksize * block_num:t_MAC.blocksize * (block_num + 1)])
        if blocks_number < len(data) / t_MAC.blocksize:
            self.mac_add_block(data[t_MAC.blocksize * blocks_number:])
        return msb(self.mac_finalize(), t_MAC.tlen)

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
        if len(tag) != okr(t_MAC.tlen):
            raise ValueError("tag: expected length {} bytes, but got {}".format(okr(t_MAC.tlen), len(tag)))
        if self.compute_mac(data) == tag:
            return True
        return False
