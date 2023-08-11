from client.client import *
from ahe_bindings.ahe_bindings import Ahe
import os


keyManagementAddresses = ["http://localhost", "http://localhost", "http://localhost"]
ports = [6951, 6952, 6953]
scriptDir = os.path.dirname(__file__)
soDir = os.path.join(scriptDir, "../../ahe-library/build/libahe.so")
wallet_dir = os.path.join(scriptDir, "client/wallets/")

def main():
    # initiate a library
    a = Ahe(soDir)
    a.SetScheme("maabe")

    # specify a new device named machine123 which also has admin attribute
    uuid = "machine123"
    attribs = [uuid, "admin"]
    wallets = {}
    wallets["pub_keys"] = wallet_dir + "wallet-" + uuid + ".pub"
    wallets["sec_keys_" + uuid] = wallet_dir + "wallet-" + uuid + ".sec"
    # if the device does not have a SIM it needs to save a signature key as well
    wallets["sig_key_" + uuid] = wallet_dir + "wallet-" + uuid + ".sig"

    # onboard device machine123
    # get a public key from the key authorities
    savePubToWallet(a, keyManagementAddresses, ports, wallets["pub_keys"])
    # get private keys from the key authorities
    saveSecToWallet(a, keyManagementAddresses, ports, wallets["sec_keys_" + uuid], uuid, attribs)
    # generate a public signature verification key and post it online
    verKey = a.GenerateSigningKeys(wallets["sig_key_" + uuid])
    postVerificationKey(keyManagementAddresses[0], ports[0], uuid, verKey)

    # encrypt and sign data (return is a json string)
    enc = encryptAndSign(a, ["message1", "message2"], ["auth1:machine123", "auth2:admin AND auth3:admin"],
                      wallets["pub_keys"], wallets["sig_key_" + uuid])

    # check signature of encrypted data and decrypt it
    m = verifyAndDecrypt(a, enc, wallets["sec_keys_" + uuid], None, None)

if __name__ == "__main__":
    main()
