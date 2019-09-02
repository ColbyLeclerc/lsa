# coding=utf-8
import math
from functools import reduce
import random

"""
Note on implementation: This is an early prototype of the Lucente Stabile Atkins (LSA) Cryptosystem meant as a 
proof-of-concept, for demonstrative purposes only. As such, the algorithm below is not designed particularly for 
robustness, nor is it representative of the most-efficient practices or programming styles.

This program is meant as a demonstration of the LSA algorithm, and is not cryptographically secure according to
industry best practices of implementing cryptographic systems. Efforts at a more robust program have been spent
towards our closed-source C++ version of the LSA, which uses cryptographic libraries for computation.
"""


def main():
    """
    Set plaintext_str to any, all lowercase (with special characters '(', ' ', ')' ), string, such that the length
    of characters is less than or equal to the amount of keys returned in the function `get_enc_key_set()`.

    To add more characters, add to the list returned in the function `get_alpha_num_lst()`
    Further, to encrypt/decrypt longer strings, you can add more keys to `get_enc_key_set()`

    Keys found using LSA key sharing algorithm, found in 'Multiple length key sharing with the Lucente
    Stabile Atkins (LSA) Cryptosystem' paper. The program used to find such keys is not provided
    here

    """

    key_lst = get_enc_key_set()

    plaintext_str = "lucente stabile atkins (lsa) cryptosystem"

    if len(plaintext_str) > len(key_lst):
        print("Error: key list must be greater than or equal to the length of characters in plaintext string "
              "(spaces included). Add {0} more keys to encrypt the string `{1}`".format(len(plaintext_str) -
                                                                                        len(key_lst), plaintext_str))
        return

    print("Key lst = {0}".format(key_lst))

    cipher_lst = encrypt_string_multikey(plaintext_str, key_lst)

    print("Cipher lst = {0}".format(cipher_lst))

    plaintext_decrypt = decrypt_string_multikey(cipher_lst, key_lst)

    print("Decrypted plaintext = {0}".format(plaintext_decrypt))


def encrypt_string_multikey(string_plntxt, key_lst):
    """
    Given a plaintext string, iterates through each character, encrypting the element using a key from the passed
    key list.

    Note: `key_lst` must be >= len(string_plntxt)

    :param string_plntxt: plaintext string to encrypt
    :param key_lst: list of keys to use for encryption.
    :return: list of cipher C such that C = {c, Σ} ( [{c, Σ}, ..] )
    """
    cipher_lst = []
    key_pntr = 0

    for char in string_plntxt:
        cipher_lst.append(encrypt(key_lst[key_pntr], char))
        key_pntr += 1

    return cipher_lst


def decrypt_string_multikey(cipher_lst, key_lst):
    """
    Given a plaintext string, iterates through each character, decrypting the element using the key from the passed
    key list.

    Note: `key_lst` must be >= len(string_plntxt), and must be the same key list used to encrypt. Order of elements
    must be consistent

    :param string_plntxt: plaintext string to encrypt
    :param key_lst: list of keys to use for decryption.
    :return: decrypted plaintext
    """

    plaintext_decrypted = ""
    key_pntr = 0

    for cipher in cipher_lst:
        plaintext_decrypted += str(decrypt(cipher, key_lst[key_pntr]))
        print("plaintext_decrypted: {0}".format(plaintext_decrypted))
        key_pntr += 1

    return plaintext_decrypted


def decrypt(cipher, key):
    """
    Given a key and cipher, finds the associated plaintext. Cipher c is a tuple such that C = {c, Σ}

    :param cipher: Cipher C
    :param key: Key used for encrypting cipher C
    :return: plaintext character
    """

    u_group_int = get_u_group_int(key)
    u_group = generate_u_group(u_group_int)

    print("decrypting cipher {0} using key {1} in U({2}) of length {3}".format(
        cipher, key, u_group_int, len(u_group)))

    plaintext_index = find_plaintext_index(u_group, u_group_int, cipher, key)

    # print("Plaintext index: {0}".format(plaintext_index))

    return get_plaintext(plaintext_index, u_group)


def encrypt(key, plaintext):
    """
    Given a key, and plaintext, finds appropriate u_group, it's space, and encrypts to a cipher tuple such that
    C = {c, Σ}

    :param key: Encryption key
    :param plaintext: The position in the group to send (i.e. 6 would encrypt to the 6th element of the group)
    :return: cipher C
    """

    u_group_int = get_u_group_int(key)
    u_group = generate_u_group(u_group_int)

    plaintext_tpl_indices_lst = find_all_plaintext_indices(plaintext, u_group)

    plaintext_tpl = pick_plaintext_tuple(plaintext_tpl_indices_lst)

    plaintext_index = plaintext_tpl[1]

    elem_sent = u_group[plaintext_index - 1]

    cipher_c = get_cipher_c(u_group, elem_sent, u_group_int)

    sigma = find_sigma(u_group, plaintext_index, u_group_int, key)

    return cipher_c, sigma


def get_enc_key_set():
    """
        List of keys to use for multi-key encryption. If there are more keys than letters, the algorithm works. If there
        are less, the algorithm breaks. We can add in key reuse, and have the algorithm be 'smarter'
    """
    return [
        9000, 6350, 9175, 1204, 6659, 8492, 2838, 5740, 8464, 9865, 4811, 9035, 1520, 2897,
        4440, 7433, 2189, 3324, 6334, 8398, 3035, 1663, 2984, 7944, 7753, 9478, 7158, 4065,
        9537, 1869, 6813, 6689, 4259, 8284, 5248, 2529, 4897, 8737, 3445, 8565, 4362, 1567,
        7229, 6123, 4324, 9562, 1949, 5710, 1406
    ]


def pick_plaintext_tuple(char_tpl_lst):
    """
    Given a list of possible character tuples to use (of same character), chooses one at (semi) randomness.

    list of possible character tuples as: [(char, ind), ..] such that `char` is the character, and `ind`
    is it's corresponding mapped location against the u_group space

    :param char_tpl_lst: list of tuples
    :return: the chosen tuple (char, ind)
    """

    chosen_tupl = char_tpl_lst[random.randint(0, len(char_tpl_lst) - 1)]

    return chosen_tupl


def get_plaintext(plaintext_index, u_group):
    """
    Given the plaintext index, and u_group, finds the corresponding plaintext character
    :param plaintext_index: Index of plaintext to find
    :param u_group: u_group space used
    :return: plaintext element
    """

    char_set = get_alpha_num_lst()

    char_pointer = 0

    tuple_lst = []

    for elem in u_group:

        char_set_elem = char_set[char_pointer]

        tuple_lst.append((char_set_elem, elem))
        char_pointer += 1

        if char_pointer is len(char_set):
            char_pointer = 0

    return tuple_lst[plaintext_index][0]


def find_all_plaintext_indices(plaintext, u_group):
    """
    Finds all the indices for the passed character that map to the u_group, according to the hard-coded
    `get_alpha_num_lst`.  Note there can exists a one-to-many mapping relationship for each character
    in `get_alpha_num_lst`

    :param plaintext: plaintext character to find index of each character
    :param u_group: u_group space used
    :return: list of character tuples [(char, ind), ...] where `char` is the character, and `ind` is it's
    respective index
    """

    char_set = get_alpha_num_lst()

    char_tpl_lst = []
    char_pointer = 0
    u_index = 0

    for i in range(1, len(u_group)):

        char_set_elem = char_set[char_pointer]

        if str(char_set_elem) == str(plaintext):
            char_tpl_lst.append((char_set_elem, u_index))

        char_pointer += 1

        if char_pointer is len(char_set):
            char_pointer = 0
        u_index += 1

    if len(char_tpl_lst) is 0:
        raise ValueError('char_tpl_lst is empty. plaintext: {0} u_group size: {1}'.format(
            plaintext, len(u_group)))

    return char_tpl_lst


def u_int_gen(prime_lim=4000, exp_lim=17):
    """
    Finds u_group_ints such that:

    I) k < n.
    II)n=pt,n=2·pt where p is an odd prime number and t ∈ N.
    III) For any β ∈ Z that satisfies I) and II) it must be the case that n ≤ β.

    :param prime_lim: Limit for prime generation
    :param exp_lim: exponent limit for t
    :return: list of u_group_ints that satisfy the above properties
    """

    primes = gen_primes(prime_lim)

    lst_p_t = []

    exp_list = range(1, exp_lim + 1)

    for p in primes:
        for t in exp_list:
            if p > 0:
                p_of_t = p ** t
                two_p_t = 2 * (p ** t)
                if p_of_t > 150000:
                    break
                lst_p_t.append(two_p_t)
                if p_of_t not in lst_p_t:
                    lst_p_t.append(p_of_t)

    lst_p_t.sort()

    return lst_p_t


def get_u_group_int(key):
    """
    Finds the next largest int n above the key for use as the u_group_int such that

    I) k < n.
    II)n=pt,n=2·pt where p is an odd prime number and t ∈ N.
    III) For any β ∈ Z that satisfies I) and II) it must be the case that n ≤ β.

    Note depending on key size, the parameters 'prime_lim' and 'exp_lim' may need to be changed

    :param key: Chosen key
    :return: Returns an n that satisfies the above properties, assuming `prime_lim` and `exp_lim` are
    sufficiently large
    """
    for elem in u_int_gen(prime_lim=4000, exp_lim=17):
        if int(elem) > int(key):
            return elem


def generate_u_group(u_group_int):
    """
    Generates a cyclic u_group using u_group_int
    :param u_group_int: U Group num
    :return: list of elements in cyclic u_group
    """

    group_result = []

    for i in range(1, u_group_int):
        if math.gcd(i, u_group_int) == 1:
            group_result.append(i)

    return group_result


def find_plaintext_index(u_group, u_group_int, cipher, key):
    """
    Finds the index of the plaintext

    :param u_group: u_group space used
    :param u_group_int: u_group integer
    :param cipher: cipher C tuple such that C = {c, Σ}
    :param key: key used for encryption
    :return: plaintext index
    """

    sigma = cipher[1]
    seed_num = cipher[0]

    reverse_u_group = u_group[::-1]

    product = seed_num
    sigma_count = 0
    sigma_limit_found = False
    plaintext_elem = 0

    for elem in reverse_u_group:
        if sigma_limit_found:
            plaintext_elem = elem
            break

        product *= elem
        if (product % u_group_int) - u_group_int % -1 == (u_group_int - 1):
            sigma_count += 1
        if sigma_count is sigma:
            sigma_limit_found = True

    return u_group.index(plaintext_elem) + 1


def find_sigma(u_group, plaintext, u_group_int, key):
    """
    Finds number of sigmas (used in C = {c, Σ}) for the given plaintext. See paper for explanation of sigma

    :param u_group: u_group as list of integers
    :param plaintext: plaintext to find sigma for
    :param u_group_int: u_group int used for u_group generation
    :param key: key used to find u_group int earlier in process
    :return: sigma count
    """

    seed_num = reduce((lambda x, y: x * y), u_group[0:plaintext]) % u_group_int

    u_group_after_seed = u_group[plaintext::]

    reverse_u_group = u_group_after_seed[::-1]

    product = seed_num

    sigma_count = 0

    for elem in reverse_u_group:
        product *= elem

        if (product % u_group_int) - u_group_int == -1:
            sigma_count += 1

    return sigma_count


def get_cipher_c(u_group, chosen_elem, u_group_int):
    """
    Generates the cipher text using the given modulus, and group.
    The result is the 'c' in C = {c, Σ}
    If used correctly, then the following will be true:
    Let <g-v> be the generated value from multiplying the group by the
    passed modulus. Let <m> be the passed modulus:
    key ≡ ( <g-v> mod <m> ) - <m>

    :param u_group: u_group as list of integers
    :param chosen_elem: Element chosen
    :param u_group_int: u_group int used for u_group generation
    :return Cipher c ( seen in C = {c, Σ} )
    """

    product_res = 1

    for elem in u_group:
        product_res = (product_res * elem)
        if elem is chosen_elem:
            break

    product_res = product_res % u_group_int

    return product_res


def gen_primes(limit):
    """
    Given an arbitrary limit, generates a list of primes.

    :param limit: max prime to find
    :return: list of primes such that all elements are prime, and less than `limit`, after 2
    """

    primes = []
    for possiblePrime in range(2, limit):

        is_prime = True
        for num in range(2, int(possiblePrime ** 0.5) + 1):
            if possiblePrime % num == 0:
                is_prime = False
                break

        if is_prime:
            primes.append(possiblePrime)

    # Return all elements after 2
    return primes[1::]


def get_alpha_num_lst():
    """
    Hard-coded list of plaintext elements to map against the u_group.

    :return: Hard-coded list of plaintext characters
    """
    return [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
            'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', ' ', '(', ')']


if __name__ == "__main__":
    main()
