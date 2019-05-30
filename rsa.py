#!/usr/bin/python3
# -*-coding:UTF-8 -*

import math
import sys
from random import *
from feistel import *


class UTILS:
    def __init__(self, *args, **kwargs):
        return super().__init__(*args, **kwargs)

    def getRandomPrime():
        """Fonction de génération de nombre premier"""
        nbr = 0
        while(True):
            nbr = randint(555555, 9999999)
            if(UTILS.isPrime(nbr)):
                break
        return nbr

    def pgcd(a, b):
        """pgcd(a,b): calcul du 'Plus Grand Commun Diviseur' entre les 2 nombres entiers a et b"""
        while b != 0:
            r = a % b
            a, b = b, r
        return a

    def runEuclide(a, b):
        """Implémentation de l'algorithme de d'Euclide généralisé"""
        if(a < b):
            tmp = a
            a = b
            b = tmp
        r0 = a
        r1 = b
        r2 = 1
        Q = []
        Q.append(0)
        while(r2 > 0):
            q1 = r0//r1
            r2 = r0 - q1*r1
            if(r2 >= 1):
                Q.append(q1)
            # print(r0, " = ", r1, "x", q1, "+", r2)
            r0 = r1
            r1 = r2
        return Q

    def generateE(phi):
        """Génération d'un nombre premier avec l'indicateur d'Euleur """

        e = randint(1, phi//30)
        while(True):
            pgcd = UTILS.pgcd(phi, e)
            if pgcd == 1:
                break
            e = randint(1, phi//30)
        return e

    def isPrime(nbr):
        """ Fonction de test de primalité """
        state = True
        if nbr <= 1:
            return False
        elif(nbr in [2, 3, 5, 7, 11]):
            state = True
        elif nbr % 2 == 0:
            return False
        else:
            root = math.sqrt(nbr)
            i = 3
            while(i <= root):
                if(nbr % i == 0):
                    state = False
                    break
                i += 2
        return state

    def V(tab, level):
        """Suite utilitaire pour l'algorithme d'Euclide généralisé"""
        if level == 0:
            return 0
        elif level == 1:
            return 1
        else:
            return UTILS.V(tab, level-2) - tab[level-1] * UTILS.V(tab, level-1)

    def U(tab, level):
        """Suite utilitaire pour l'algorithme d'Euclide généralisé"""
        if level == 0:
            return 1
        elif level == 1:
            return 0
        else:
            return UTILS.U(tab, level-2) - tab[level-1] * UTILS.U(tab, level-1)

    def modularInverse(a, b):
        """Fonction de calcul de l'inverse modulaire"""
        tab = UTILS.runEuclide(a, b)
        if a >= b:
            inv = (UTILS.U(tab, len(tab)) + b) % b
        else:
            inv = (UTILS.V(tab, len(tab)) + b) % b
        return inv

    def modularExponential(nbr, exp, mod):
        """Fonction de l'exponentiel modulaire"""
        result = 1
        while exp > 0:
            if(exp & 1) > 0:
                result = (result * nbr) % mod
            exp >>= 1
            nbr = (nbr * nbr) % mod
        return result


class RSA:
    """Gestion de la générarion des clés et modules RSA"""

    def __init__(self):
        self.p = UTILS.getRandomPrime()
        self.q = UTILS.getRandomPrime()
        self.n = self.p * self.q
        self.phi = (self.p - 1)*(self.q - 1)
        self.e = UTILS.generateE(self.phi)
        self.privateKey = UTILS.modularInverse(self.e, self.phi)


class Client:
    """Class du client qui a besoin de partager un secret"""

    def __init__(self):
        self.rsa = RSA()

    def fromTextToAscii(message):
        """Converstion d'un chaine de caractères en concaténation de nombre ascii"""
        return int("".join(str(ord(c).__str__().zfill(3)) for c in message))

    def fromAsciiToText(ascii):
        """Conversion d'un nombre en chaine de caractère"""
        keys = []
        for i in range(len(ascii), 0, -3):
            j = i - 3
            if(j < 0):
                j = 0
            keys.append(ascii[j:i])
        keys.reverse()
        message = ""
        for code in keys:
            message += chr(int(code))
        return message

    def encryptRSA(self, message, e, n):
        """Fonction de codage RSA"""
        message = Client.fromTextToAscii(message)
        secret = UTILS.modularExponential(message, e, n)
        return Client.fromAsciiToText(str(secret))

    def decryptRSA(self, message):
        """Fonction de décodage RSA"""
        message = Client.fromTextToAscii(message)
        secret = UTILS.modularExponential(
            message, self.rsa.privateKey, self.rsa.n)
        return Client.fromAsciiToText(str(secret))

    def getRandomMsg():
        """Fonction de génération d'un nombre aléatoire de 4 caractères"""
        rand_msg = ""
        for i in range(0, 4):
            rand_msg += chr(randint(65, 90))
        return rand_msg


if __name__ == "__main__":

    """Corps du programme principale"""

    # création du client A
    A = Client()
    # création du client B
    B = Client()
    print("Clé public de A :(n, e) = (", A.rsa.n, ",", A.rsa.e, ")")
    print("Clé public de B :(n, e) = (", B.rsa.n, ",", B.rsa.e, ")\n")
    # 1) A envoie le message 'AB ?!' vers B
    messageA = "AB?!"
    #   a) cryptage du message avec la clé publique de B
    secretAB = A.encryptRSA(messageA, B.rsa.e, B.rsa.n)
    print("A envoie à B le message", messageA, "crypter en", secretAB)
    #   b) B décrypte le message à l'aide de sa clé privé
    messageB = B.decryptRSA(secretAB)
    print("B recoit de A le message secret",
          secretAB, "et le décrypt en", messageB, "\n")
    # 2) B envoie à A le message AB OK
    messageB = "ABOK"
    #   a) cryptage du message avec la clé publique de B
    secretBA = B.encryptRSA(messageB, A.rsa.e, A.rsa.n)
    print("Maintenant B envoie à A le message",
          messageB, "crypter en", secretBA)
    #   b) A décrypte le message à l'aide de sa clé privé
    messageA = A.decryptRSA(secretBA)
    print("A recois de B le message secret",
          secretBA, "et le décrypt en", messageA, "\n")
    # 3) A reçoit bien le message de confirmation
    #   a) A genere un message aléatoire
    rand_messageA = Client.getRandomMsg()
    rand_secretAB = A.encryptRSA(rand_messageA, B.rsa.e, B.rsa.n)
    print("A a générer aléatoirement le message ", rand_messageA,
          " et envoie sa version crypté", rand_secretAB)
    #   b) B décrypte le message à l'aide de sa clé privé
    rand_messageB = B.decryptRSA(rand_secretAB)
    print("B recoit le message crypté aléatoire",
          rand_secretAB, "et le décrypte en", rand_messageB)

    #   c) B crypte le message aléatoire et le renvoie à A
    rand_secretBA = B.encryptRSA(rand_messageB, A.rsa.e, A.rsa.n)
    print("B renvoie à son tour le message crypté aléatoire",
          rand_messageB, "crypté en ", rand_secretBA)
    #   d) A reçois de nouveau son message aléatoire et le décrypte
    rand_messageA = A.decryptRSA(rand_secretBA)
    print("A reçois de nouveau son message aléatoire", rand_secretBA, "et le décrypte en",
          rand_messageA, "\n")

    # 4) A et B génèrent chacun un mot de pass
    passwordA = decrypt_binaire_word(xor(encrypt_binaire_word("ABOK"),
                                         encrypt_binaire_word(rand_messageA)))
    print("A génère le mot de pass:", passwordA)

    passwordB = decrypt_binaire_word(xor(encrypt_binaire_word("ABOK"),
                                         encrypt_binaire_word(rand_messageB)))
    print("B génère le mot de pass:", passwordB, "\n")

    # 5) A envois le message crypter avec la méthode de feistel
    messageA = "MESSAGE CRYPTER AVEC FEISTEL"
    feistel_msg_A = encrypt_feistel(messageA, passwordA)
    print("A crypt les message", messageA, "en", feistel_msg_A, "\n")

    # 6) A envois le message crypter avec la méthode de feistel
    messageB = decrypt_feistel(feistel_msg_A, passwordB)
    print("B décrypt le message de A en ", messageB)
