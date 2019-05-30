#!/usr/bin/python3
# -*-coding:UTF-8 -*
import sys




#Dictionnaire de correspondance  entre lettre et entier
dic = {
    "A": 0,"B": 1,"C": 2,"D": 3,"E": 4,"F": 5,"G": 6,"H": 7,"I": 8,"J": 9,"K": 10,"L": 11,"M": 12,"N": 13,"O": 14,"P": 15,"Q": 16,"R": 17,"S": 18,"T": 19,"U": 20,"V": 21,"W": 22,"X": 23,"Y": 24,"Z": 25," ": 26,".": 27,",": 28,"'": 29,"!": 30,"?": 31
}

#dictionnaire de conrrespondance inverse
rev = {
    0: "A", 1: "B", 2: "C", 3: "D", 4: "E", 5: "F", 6: "G", 7: "H", 8: "I", 9: "J", 10: "K", 11: "L", 12: "M", 13: "N", 14: "O", 15: "P", 16: "Q", 17: "R", 18: "S", 19: "T", 20: "U", 21: "V", 22: "W", 23: "X", 24: "Y", 25: "Z", 26: " ", 27: ".", 28: ",", 29: "'", 30: "!", 31: "?"
}

def dec2bin(nbr):
    """Fonction ce conversion d'un décimal en entier"""
    digits = []
    while(nbr >= 2):
        tmp = nbr % 2
        digits.append(tmp)
        nbr = nbr // 2
    if nbr != 0:
        digits.append(nbr)
    while len(digits) < 5:
        digits.append(0)
    digits.reverse()
    return digits


def bin2dec(digits):
    """Fonction ce conversion d'un  entier en décimal"""
    dec_nbr = 0
    e = len(digits)
    for i in digits:
        e -= 1
        dec_nbr += i * (2 ** e)
    return dec_nbr

def encrypt_binaire(el):
    """Fonction de conversion d'un caractère en binaire"""
    return dec2bin(dic[el])


def decrypt_binaire(digits):
    """Fonction de conversion d'un nombre binaire en caractère"""
    return rev[bin2dec(digits)]


def encrypt_binaire_word(msg):
    """Fonction de conversion d'un mot en binaire"""
    bin_msg = []
    for l in msg:
        bin_msg += encrypt_binaire(l)
    return bin_msg

def decrypt_binaire_word(msg):
    """Fonction de conversion d'un nombre binaire en mot"""
    init_msg = []
    for i in range(0, len(msg), 5):
        bin_msg = msg[i:i+5]
        init_msg += decrypt_binaire(bin_msg)
    return "".join(init_msg)

def left_shift(digits):
    """Fonction de décallage à gauche"""
    left = digits.pop(0)
    digits.append(left)
    return digits

def xor(bin1, bin2):
    """Fonction de OU exclusif"""
    res = []
    for i in range(0, len(bin1)):
        if(bin1[i] == bin2[i]):
            res.append(0)
        else:
            res.append(1)
    return res

def function(msg, key):
    """Fonction de cryptage utilisé par le réseau"""
    msg = left_shift(msg)
    res = xor(msg, key)
    return res

def join(list_int):
    """Fonction de conversion d'une liste de nombre binaire en chaine"""
    text = ""
    return "".join(str(x) for x in list_int)

def encrypt_feistel_bin(msg, key):
    """Fonction de cryptage d'un mot binaire par le réseau"""
    Gn = encrypt_binaire_word(msg[0:2])
    Dn = encrypt_binaire_word(msg[2:4])
    for i in range(0, 4):

        subkey = key[i]+key[(i+1) % len(key)]
        subkey = encrypt_binaire_word(subkey)
        tmp = Dn.copy()
        fn_res = function(Dn.copy(), subkey.copy())
        Dn = xor(Gn.copy(), fn_res)
        Gn = tmp

    return Gn+Dn

def decrypt_feistel_bin(msg, key):
    """Fonction de decyptage d'un mot binaire par le réseau"""
    Gn = encrypt_binaire_word(msg[0:2])
    Dn = encrypt_binaire_word(msg[2:4])

    for i in range(3, -1, -1):
        if i == 3:
            subkey = key[i]+key[0]
        else:
            subkey = key[i:i+2]
        subkey = encrypt_binaire_word(subkey)
        tmp = Gn.copy()
        fn_res = function(Gn.copy(), subkey.copy())
        Gn = xor(Dn.copy(), fn_res)
        Dn = tmp

    return Gn+Dn

def encrypt_feistel(msg, key):
    """Fonction de cryptage d'une chaine de caractère par le réseau"""
    res = ""
    for i in range(0, len(msg)//4):
        res += decrypt_binaire_word(encrypt_feistel_bin(msg[4*i:4*i+5], key))
    return res

def decrypt_feistel(msg, key):
    """Fonction de decryptage d'une chaine de caractère par le réseau"""
    res = ""
    for i in range(0, len(msg)//4):
        res += decrypt_binaire_word(decrypt_feistel_bin(msg[4*i:4*i+5], key))
    return res

if __name__ == "__main__":
    
    msg = ["AAAA??BB", "??BBAAAA", "BBAABBAA", "AABBAABB", "HELLO WORLD!", "BONJOUR LE MONDE", "QUOI DE MIEUX ?!"]
    key = ["KXCX", "FFFF", "BCGE", "A.!?", "N? !", "ZZXW", "DFAT"]
    for i in range(0, 7):
        a = encrypt_feistel(msg[i], key[i])
        print("Cryptage du msg  : ",msg[i]," avec la clé ", key[i],"==>", a)
        b = decrypt_feistel(a, key[i])
        print("Deryptage du msg : ",a," avec la clé ", key[i],"==>", b)
        print("\n")

   
    # input("\nAppuyez sur entrer pour finir...")