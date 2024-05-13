# ---------------------------- Libraries ------------------------------- #
import binascii


# ---------------------------- Classes ------------------------------- #
class TestSchiffy128:

    # Constractor
    def __init__(self):
        self.schiffy = Schiffy128()
        self.s_box = self.schiffy.s_box
        self.key = 0xdeadbeef000000000000000badc0ffee
        self.round_keys = self.schiffy.key_schedule_algorithm(self.key, 32)
        self.passed_tests = 0

    # Methods
    def full_test(self):
        """
        Executes all tests.
        :return: None
        """

        print()
        print("\033[33m" + "Testing the Schiffy128 algorithm ..." + "\033[0m")
        print()

        self.test_s_box()
        self.test_key_schedule_algorithm()
        self.test_feistel_function()
        self.test_encrypt_decrypt()

        if self.passed_tests == 4:
            print("\033[32m" + "All major tests passed successfully.\nSchiffy128 is working correctly." + "\033[0m")
            print()

        else:
            print("\033[31m" + "Some tests failed.\nSchiffy128 is not working correctly." + "\033[0m")
            print()

    def test_s_box(self):
        """
        Tests the creation of the S-Box.
        :return: None
        """

        print("\033[33m" + "Testing the S-Box ..." + "\033[0m")

        assert len(self.s_box) == 256, f"Error: The S-Box has a length of {len(self.s_box)} instead of 256."
        print("Test 1 passed successfully.")

        assert self.s_box[0] == 170, f"Error: The 1. element of the S-Box is {self.s_box[0]} instead of 170."
        print("Test 2 passed successfully.")

        assert self.s_box[1] == 155, f"Error: The 2. element of the S-Box is {self.s_box[1]} instead of 155."
        print("Test 3 passed successfully.")

        assert self.s_box[2] == 112, f"Error: The 3. element of the S-Box is {self.s_box[2]} instead of 112."
        print("Test 4 passed successfully.")

        assert self.s_box[123] == 33, f"Error: The 123. element of the S-Box is {self.s_box[3]} instead of 33."
        print("Test 5 passed successfully.")

        assert self.s_box[255] == 205, f"Error: The 255. element of the S-Box is {self.s_box[4]} instead of 205."
        print("Test 6 passed successfully.")
        self.passed_tests += 1

        print("-" * 50)
        print("\033[32m" + "All tests passed successfully." + "\033[0m")
        print()

    def test_key_schedule_algorithm(self):
        """
        Tests the key schedule algorithm.
        :return: None
        """

        print("\033[33m" + "Testing the key schedule algorithm ..." + "\033[0m")

        assert len(self.round_keys) == 32, f"Error: The number of round keys is {len(self.round_keys)} instead of 32."
        print("Test 1 passed successfully.")

        assert self.round_keys[0] == "deadbeef000000000000000bad6b3201", \
            f"Error: The 1. round key is {self.round_keys[0]} instead of deadbeef000000000000000bad6b3201."
        print("Test 2 passed successfully.")

        assert self.round_keys[1] == "56df778000000000000005d6b532cd00", \
            f"Error: The 2. round key is {self.round_keys[1]} instead of 56df778000000000000005d6b532cd00."
        print("Test 3 passed successfully.")

        assert self.round_keys[2] == "dde00000000000000175ad4cb3ebd858", \
            f"Error: The 3. round key is {self.round_keys[2]} instead of dde00000000000000175ad4cb3ebd858."
        print("Test 4 passed successfully.")

        assert self.round_keys[31] == "770feb4b3180dc3bc09870bd38e2cb5f", \
            f"Error: The 4. round key is {self.round_keys[3]} instead of 770feb4b3180dc3bc09870bd38e2cb5f."
        print("Test 5 passed successfully.")
        self.passed_tests += 1

        print("-" * 50)
        print("\033[32mAll tests passed successfully." + "\033[0m")
        print()

    def test_feistel_function(self):
        """
        Tests the Feistel function.
        :return: None
        """

        print("\033[33m" + "Testing the Feistel function ..." + "\033[0m")

        assert self.schiffy.feistel_function(0x0000000000000000, int(self.round_keys[0], 16)) == "94dfb49607c198ab", \
            f"Error: The output of the 1. round is {self.schiffy.feistel_function(0x0000000000000000, self.key)} instead of 94dfb49607c198ab."
        print("Test 1 passed successfully.")

        assert self.schiffy.feistel_function(0x94dfb49607c198ab, int(self.round_keys[1], 16)) == "b0aa7cca50e95fb1", \
            f"Error: The output of the 2. round is {self.schiffy.feistel_function(0x94dfb49607c198ab, int(self.round_keys[1], 16))} instead of b0aa7cca50e95fb1."
        print("Test 2 passed successfully.")

        assert self.schiffy.feistel_function(0xb0aa7cca50e95fb1, int(self.round_keys[2], 16)) == "1e9d6324e9783573", \
            f"Error: The output of the 3. round is {self.schiffy.feistel_function(0xb0aa7cca50e95fb1, int(self.round_keys[2], 16))} instead of 1e9d6324e9783573."
        print("Test 3 passed successfully.")

        assert self.schiffy.feistel_function(0x8a42d7b2eeb9add8, int(self.round_keys[3], 16)) == "01a6283b0f33c8f0", \
            f"Error: The output of the 4. round is {self.schiffy.feistel_function(0x8a42d7b2eeb9add8, int(self.round_keys[3], 16))} instead of 01a6283b0f33c8f0."
        print("Test 4 passed successfully.")

        assert self.schiffy.feistel_function(0xc8ef99ba72f8a579, int(self.round_keys[29], 16)) == "f7ffea032144154a", \
            f"Error: The output of the 5. round is {self.schiffy.feistel_function(0xc8ef99ba72f8a579, int(self.round_keys[4], 16))} instead of f7ffea032144154a."
        print("Test 5 passed successfully.")

        assert self.schiffy.feistel_function(0x81f3d4d01743d570, int(self.round_keys[30], 16)) == "7fac6b4146d4f4c6", \
            f"Error: The output of the 6. round is {self.schiffy.feistel_function(0x81f3d4d01743d570, int(self.round_keys[5], 16))} instead of 7fac6b4146d4f4c6."
        print("Test 6 passed successfully.")

        assert self.schiffy.feistel_function(0xb743f2fb342c51bf, int(self.round_keys[31], 16)) == "2a66d3471f7cb499", \
            f"Error: The output of the 7. round is {self.schiffy.feistel_function(0xb743f2fb342c51bf, int(self.round_keys[6], 16))} instead of 2a66d3471f7cb499."
        print("Test 7 passed successfully.")
        self.passed_tests += 1

        print("-" * 50)
        print("\033[32m" + "All tests passed successfully." + "\033[0m")
        print()

    def test_encrypt_decrypt(self):
        """
            Tests the encryption and decryption function.
            :return: None
        """

        print("\033[33m" + "Testing the encryption and decryption ..." + "\033[0m")

        encrypted_message = self.schiffy.encrypt_decrypt("00000000000000000000000000000000", hex(self.key).lstrip("0x"))
        expected_encrypted_message = "b743f2fb342c51bfab950797083f61e9"
        assert encrypted_message == expected_encrypted_message, \
            f"Error: The encrypted message is {encrypted_message} instead of {expected_encrypted_message}."
        print("Test 1 passed successfully.")

        decrypted_message = self.schiffy.encrypt_decrypt(encrypted_message, hex(self.key).lstrip("0x"), False)
        expected_decrypted_message = "00000000000000000000000000000000"
        assert decrypted_message == expected_decrypted_message, \
            f"Error: The decrypted message is {decrypted_message} instead of {expected_decrypted_message}."
        print("Test 2 passed successfully.")
        self.passed_tests += 1

        original_message = "Never gonna make you cry........"
        key = "08150000000000000000000000004711"
        encrypted_message = self.schiffy.encrypt_decrypt(string_to_hex(original_message), key)
        decrypted_message = hex_to_ascii(self.schiffy.encrypt_decrypt(encrypted_message, key, False))
        assert original_message == decrypted_message, \
            f"Error: The decrypted message is {decrypted_message} instead of {original_message}."
        print("Test 3 passed successfully.")

        print("-" * 50)
        print("\033[32m" + "All tests passed successfully." + "\033[0m")
        print()


class Schiffy128:

    # Constractor
    def __init__(self, key_size=128, number_of_rounds=32):
        self.key_size = key_size
        self.number_of_rounds = number_of_rounds
        self.s_box = self.__create_8x8_s_box()

    # Methods
    @staticmethod
    def __create_8x8_s_box() -> list[int]:
        """
        Creates a 8x8 S-Box.
        :return: A list of integers representing the S-Box.
        """

        s_x = 170
        s_box = [170]

        for _ in range(255):
            s_x = ((37 * s_x) + 9) % 256
            s_box.append(s_x)

        return s_box

    @staticmethod
    def __split_into_blocks(message: str, block_size=32) -> list[str]:
        """
        Splits the message into blocks.
        :param message: The message to be split.
        :param block_size: The size of each block.
        :return: A list of strings representing the blocks.
        """

        if len(message) % block_size != 0:
            needed_padding = block_size - (len(message) % block_size)
            message = message + "2" * needed_padding

        blocks = [message[i:i + block_size] for i in range(0, len(message), block_size)]

        return blocks

    @staticmethod
    def __rotate_left(val: int, r_bits: int, max_bits: int) -> int:
        """
        Performs a left rotation.
        :param val: The value to be rotated.
        :param r_bits: The number of bits to rotate.
        :param max_bits: The maximum number of bits.
        :return: The result of the left rotation.
        """

        r_bits %= max_bits  # Ensure the rotation is within the maximum number of bits.
        mask = (1 << max_bits) - 1

        return ((val << r_bits) | (val >> (max_bits - r_bits))) & mask

    def key_schedule_algorithm(self, key: int, n_round_keys: int) -> list[str]:
        """
        Implements the key schedule algorithm.
        :param key: The key used in the algorithm.
        :param n_round_keys: The number of round keys.
        :return: A list of strings representing the round keys.
        """

        round_keys = []
        round_key = key

        for i in range(n_round_keys):
            round_key = (self.__rotate_left(round_key, 7 * i, 128)) ^ 0xabcdef
            round_keys.append(hex(round_key).lstrip("0x").zfill(32))

        return round_keys

    def feistel_function(self, block: int, round_key: int) -> str:
        """
        Implements the Feistel function.
        :param block: The block to be processed.
        :param round_key: The round key used in the function.
        :return: A string representing the result of the function.
        """

        round_key_high = round_key >> 64
        round_key_low = round_key & 0xFFFFFFFFFFFFFFFF

        block ^= round_key_high

        block_bytes = block.to_bytes(8, byteorder='big')
        new_block_bytes = bytearray()

        for byte in block_bytes:
            new_block_bytes.append(self.s_box[byte])

        block = int.from_bytes(new_block_bytes, byteorder='big')
        block ^= round_key_low

        return hex(block).lstrip("0x").zfill(16)

    def encrypt_decrypt(self, hex_message: str, hex_key: str, encrypt=True) -> str:
        """
        Performs the encryption and decryption function.
        :param hex_message: The message to be encrypted/decrypted.
        :param hex_key: The key used in the function.
        :param encrypt: A boolean indicating whether to encrypt (True) or decrypt (False).
        :return: A string representing the encrypted/decrypted message.
        """

        if 4 * len(hex_key) == self.key_size:
            hex_blocks = self.__split_into_blocks(hex_message)
            round_keys = self.key_schedule_algorithm(int(hex_key, 16), 32)
            new_message = ""

            for block in hex_blocks:
                left_block = block[:16]
                right_block = block[16:]

                if encrypt:
                    for i in range(self.number_of_rounds):
                        temp = right_block
                        feistel_output = self.feistel_function(int(right_block, 16), int(round_keys[i], 16))
                        result = hex(int(left_block, 16) ^ int(feistel_output, 16)).lstrip("0x").zfill(16)

                        left_block = temp
                        right_block = result

                    new_message += left_block + right_block

                else:
                    for i in reversed(range(self.number_of_rounds)):
                        temp = left_block
                        feistel_output = self.feistel_function(int(left_block, 16), int(round_keys[i], 16))
                        result = hex(int(right_block, 16) ^ int(feistel_output, 16)).lstrip("0x").zfill(16)

                        right_block = temp
                        left_block = result

                    new_message += left_block + right_block

            return new_message

        else:
            raise ValueError("The key size must be 128 bits.")


# ---------------------------- Functions ------------------------------- #
def string_to_hex(s):
    """
    Converts a string to hexadecimal.
    :param s: The string to be converted.
    :return: The hexadecimal representation of the string.
    """
    return binascii.hexlify(s.encode()).decode()


def hex_to_ascii(h):
    """
    Converts hexadecimal to a string.
    :param h: The hexadecimal to be converted.
    :return: The string representation of the hexadecimal.
    """
    return binascii.unhexlify(h.encode()).decode()


def create_binary_file(file_name: str, content: str):
    """
    Creates a binary file.
    :param file_name:
    :param content:
    :return:
    """
    with open(file_name, "wb") as f:
        f.write(bytes.fromhex(content))


def read_binary_file(file_name: str):
    """
    Reads a binary file.
    :param file_name:
    :return:
    """
    with open(file_name, "rb") as f:
        return f.read().hex()


def main():
    """
    Main function of the program.
    :return: None
    """

    # Variables
    test = TestSchiffy128()
    schiffy = Schiffy128()

    excellent_message ="\x1b[36;41m              Never gonna make you cry              \x1b[0m"
    excellent_hex = string_to_hex(excellent_message)
    key = "08150000000000000000000000004711"

    # Body
    test.full_test()

    byte_count = len(excellent_hex) // 2
    print(f"The message has {byte_count} bytes.")

    encrypted_message = schiffy.encrypt_decrypt(excellent_hex, key)
    create_binary_file("ciphertext.bin", encrypted_message)

    binary_content = read_binary_file("ciphertext.bin")
    decrypted_message = schiffy.encrypt_decrypt(binary_content, key, False)
    print(f"The decrypted message is: {hex_to_ascii(decrypted_message)}")


# ------------------------------ Main ---------------------------------- #

if __name__ == "__main__":
    main()
