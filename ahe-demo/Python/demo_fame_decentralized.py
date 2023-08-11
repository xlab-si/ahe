from client.client import *
from ahe_bindings.ahe_bindings import Ahe
from ahe_bindings.ahe_types import FameCipher
import os

# https
keyManagementAddresses = ["https://localhost", "https://localhost", "https://localhost"]
keyManagementPorts = [6800, 6801, 6802]
signatureManagementAddress = "https://localhost"
signatureManagementPort = 6902

scriptDir = os.path.dirname(__file__)
soDir = os.path.join(scriptDir, "../../ahe-library/prebuild/linux-x86-64/libahe.so")
wallet_dir = os.path.join(scriptDir, "client/wallets/")
# since https is used with self-signed certificate, the certificate of the certificate authority is needed
ca = "../cert/HEkeyCA.crt"
# ca = None

def main():
    # initiate a library
    a = Ahe(soDir)
    a.SetScheme("fame")

    # specify a new device named machine123 which also has admin attribute
    uuid = "machine123_for_dec_fame"
    attribs = [uuid, "admin"]
    wallets = {}
    wallets["pub_keys"] = wallet_dir + "wallet-" + uuid + ".pub"
    wallets["sec_keys_" + uuid] = wallet_dir + "wallet-" + uuid + ".sec"
    # if the device does not have a SIM it needs to save a signature key as well
    wallets["sig_key_" + uuid] = wallet_dir + "wallet-" + uuid + ".sig"

    # onboard device machine123
    # get a public key from the key authorities
    saveDecPubToWallet(a, keyManagementAddresses, keyManagementPorts, wallets["pub_keys"], ca)
    # get private keys from the key authorities
    saveDecSecToWallet(a, keyManagementAddresses, keyManagementPorts, wallets["sec_keys_" + uuid], uuid, attribs, ca)

    # generate a public signature verification key and post it online (this is possible if the device has
    verKey = a.GenerateSigningKeys(wallets["sig_key_" + uuid])
    proof = postVerificationKey(signatureManagementAddress, signatureManagementPort, uuid, verKey, ca)

    # encrypt and sign data (return is a json string)
    enc = encryptAndSign(a, ["message1", "message2"], ["machine123_for_dec_fame", "admin AND machine123_for_dec_fame"],
                         wallets["pub_keys"], wallets["sig_key_" + uuid], proof)

    # check signature of encrypted data and decrypt it
    m = verifyAndDecrypt(a, enc, wallets["sec_keys_" + uuid], uuid, wallets["pub_keys"], ca)

    # alternatively if no signatures are used one can directly encrypt a message using a policy and a public key
    pk = parseWalletPub(a, wallets["pub_keys"])
    enc2 = a.Encrypt("message3", "machine123_for_dec_fame", pk)
    # the return is a python Ciphertext object hence we need to change it to a string
    enc2string = ",".join(enc2.toStringList())
    print("* Single message encrypted\n")
    print(enc2string + "\n\n")

    # if no signatures are used, we can directly decrypt the message using the private key
    enc3 = FameCipher(enc2string.split(","))
    ks = parseWalletSec(a, wallets["sec_keys_" + uuid])
    m2 = a.Decrypt(enc3, ks, pk)
    print("* Single message decrypted\n")
    print(m2 + "\n")


if __name__ == "__main__":
    main()
