import requests
import json

from ahe_bindings.ahe_types import MaabePubKey
from ahe_bindings.ahe_types import FamePubKey
from ahe_bindings.ahe_types import MaabeKey
from ahe_bindings.ahe_types import FameKey


# wallet functions
def parseWalletPub(a, walletFilename):
    if a.scheme_type == "maabe":
        pks = {}
        w = open(walletFilename)
        fields = []
        for line in w.readlines():
            line = line.strip()
            if len(line) == 0:
                continue
            fields += line.split(" ")
        pks["wallet"] = MaabePubKey(fields)
        w.close()
        return pks
    if a.scheme_type == "fame":
        w = open(walletFilename)
        pk = w.readline()
        w.close()
        return FamePubKey(pk)

def parseWalletSec(a, walletFilename):
    w = open(walletFilename)

    if a.scheme_type == "maabe":
        ks = []
        for line in w.readlines():
            line = line.strip()
            if len(line) == 0:
                continue
            if len(line) >= 2 and line[0:2] == "# ":
                continue
            fields = line.split(" ")
            k = MaabeKey(fields)
            ks.append(k)
        w.close()

        return ks

    if a.scheme_type == "fame":
        w = open(walletFilename)
        ks = []
        for line in w:
            line = line.strip()
            ks.append(line)
        w.close()
        return FameKey(ks)

def savePubToWallet(a, address, port, walletFilename, ca=None):
    w = open(walletFilename,
             "w")
    pks = getPubKeys(a, address, port, ca)
    if a.scheme_type == "maabe":
        for ID in pks:
            data = pks[ID].toStringList()
            for i in range(len(data) // 3):
                w.write(data[3 * i + 0])
                w.write(" ")
                w.write(data[3 * i + 1])
                w.write(" ")
                w.write(data[3 * i + 2])
                w.write("\n")
            w.write("\n")
    if a.scheme_type == "fame":
        w.write(pks)

    w.close()

def saveDecPubToWallet(a, addresses, ports, walletFilename, ca=None):
    w = open(walletFilename,
             "w")
    for i in range(len(addresses)):
        address = addresses[i]
        port = ports[i]
        pksi = getPubKeys(a, address, port, ca)
        if i == 0:
            pks = pksi
        else:
            assert pksi == pks

    w.write(pks)

    w.close()

def saveSecToWallet(a, address, port, walletFilename,
                    uuid, attribs, ca=None):
    w = open(walletFilename,
             "w")

    if a.scheme_type == "maabe":
        keys = []
        for i in range(1, 3+1):
            port_i = str(port[i-1])
            ID = "auth" + str(i)
            ats = [ID + ":" + at for at in attribs]
            for k in getAuthAttributeKeys(a,
                                          address[i-1],
                                          port_i,
                                          uuid,
                                          ats,
                                          ca):
                keys.append(k)
        print("\n* Obtained decryption keys:\n")
        for k in keys:
            print(" ".join(k.toStringList()))
        print("")
        for k in keys:
            data = k.toStringList()
            w.write(" ".join(data))
            w.write("\n")

    if a.scheme_type == "fame":
        port = str(port)
        k = getAuthAttributeKeys(a, address, port, uuid, attribs, ca)
        print("\n* Obtained decryption keys:\n")
        print(k)
        print("")
        w.write(k)

    w.close()

# network functions
def saveDecSecToWallet(a, addresses, ports, walletFilename,
                       uuid, attribs, ca=None):
    w = open(walletFilename,
             "w")
    rand_keys = [None for _ in range(len(addresses))]
    enc_keys = ""
    for i in range(len(addresses)-1, -1, -1):
        port = str(ports[i])
        import secrets
        rand_key = secrets.token_hex(16)
        rand_keys[i] = rand_key
        k = getDecAuthAttributeKeys(a, addresses[i], port, uuid, attribs, rand_key, ca)
        print("\n* Obtained decryption keys:\n")
        # print(i, k)
        # print("")
        if i == 0:
            enc_keys = k

    ks = a.JoinFameDecAttribKeys(enc_keys, rand_keys)

    w.write("\n".join(ks.toStringList()))

    w.close()

    return

def getAuthPubKeys(a, authAddress,
                   authPort, ca=None):
    url = authAddress + ":" + str(authPort) + "/pubkeys"
    if ca is None:
        r = requests.get(url)
    else:
        r = requests.get(url, verify=ca)

    if not r.ok:
        return None
    if a.scheme_type == "maabe":
        pk = a.PubKeyFromJSON(r.content.decode('utf-8'))
        return pk
    elif a.scheme_type == "fame":
        pk = r.content.decode('utf-8')
        return pk

def getAuthAttributeKeys(a,
                         authAddress,
                         authPort,
                         uuid,
                         attribs,
                         ca):
    url = authAddress + ":" + str(authPort) + "/get-attribute-keys"
    jsonDict = {"uuid": uuid, "attributes": []}
    for at in attribs:
        jsonDict["attributes"].append(at)
    jsonBytes = json.dumps(jsonDict)
    headers = {'content-type': 'application/json'}
    if ca is None:
        r = requests.post(url,
                          data=jsonBytes,
                          headers=headers)
    else:
        r = requests.post(url,
                          data=jsonBytes,
                          headers=headers,
                          verify=ca)

    if not r.ok:
        return None
    if a.scheme_type == "maabe":
        ks = a.AttributeKeysFromJSON(r.content.decode('utf-8'))
    elif a.scheme_type == "fame":
        ks = r.content.decode('utf-8')

    return ks

def getDecAuthAttributeKeys(a,
                            authAddress,
                            authPort,
                            uuid,
                            attribs,
                            randKey,
                            ca):
    url = authAddress + ":" + str(authPort) + "/get-attribute-keys"
    jsonDict = {"uuid": uuid, "attributes": [], "sec_key": randKey}
    for at in attribs:
        jsonDict["attributes"].append(at)
    jsonBytes = json.dumps(jsonDict)
    headers = {'content-type': 'application/json'}

    r = requests.post(url,
                      data=jsonBytes,
                      headers=headers,
                      verify=ca)
    if not r.ok:
        return None
    ks = r.content.decode('utf-8')

    return ks

def getPubKeys(a, address, port, ca):
    if a.scheme_type == "maabe":
        pks = {}
        for i in range(1, 3+1):
            port_i = port[i-1]
            ID = "auth" + str(i)
            pks[ID] = getAuthPubKeys(a, address[i-1],
                                     port_i)
        print("\n* Obtained public keys:\n")
        for i, ID in enumerate(pks):
            print("=== " + ID + " === at ", address[i] + ":" + str(port[i]))
        #     print("\n".join(pks[ID].toStringList()))
        print("")
        return pks

    if a.scheme_type == "fame":
        pk = getAuthPubKeys(a, address,
                            port, ca)
        print("\n* Obtained public keys:\n")
        print("=== key authority === at ", address, port)
        # print(pk)
        #     print("\n".join(pks[ID].toStringList()))
        print("")
        return pk

def getAttribKeys(address):
    ks = []
    for i in range(1, 3+1):
        port = str(6900 + i)
        ID = "auth" + str(i)
        for k in getAuthAttributeKeys(address,
                                      port,
                                      "RecoveryTeamAdmin",
                                      [ID+":admin",
                                       ID+":recovery",
                                       ID+":machine123"]):
            ks.append(k)
    print("\n* Obtained decryption keys:\n")
    for k in ks:
        print(" ".join(k.toStringList()))
    print("")

def getVerificationKey(authAddress,
                       authPort,
                       uuid,
                       ca=None):
    url = authAddress + ":" + str(authPort) + "/pub-signature-keys"
    jsonDict = {"uuid": uuid, "verkey": ""}
    jsonBytes = json.dumps(jsonDict)
    headers = {'content-type': 'application/json'}
    if ca is None:
        r = requests.post(url,
                          data=jsonBytes,
                          headers=headers)
    else:
        r = requests.post(url,
                          data=jsonBytes,
                          headers=headers,
                          verify=ca)
    if not r.ok:
        return None
    verkey = json.loads(r.content)
    print("\n* Obtained a signature verification key from the key management:\n")
    print(verkey)
    print("")

    return verkey

def postVerificationKey(authAddress,
                        authPort,
                        uuid,
                        verKey,
                        ca=None):
    url = authAddress + ":" + str(authPort) + "/pub-signature-keys"
    jsonDict = {"uuid": uuid, "verkey": verKey}
    jsonBytes = json.dumps(jsonDict)
    headers = {'content-type': 'application/json'}
    if ca is None:
        r = requests.post(url,
                          data=jsonBytes,
                          headers=headers)
    else:
        r = requests.post(url,
                          data=jsonBytes,
                          headers=headers,
                          verify=ca)
    if not r.ok:
        print("error posting pubkey")
        return

    print("\n* Shared a public signature verification key:\n")
    print(jsonBytes)
    print("received proof")
    print(r.content)
    print("")

    return r.content.decode('UTF-8')

def encryptAndSign(a, messages, policies, wallet, sigWallet, proof=None):
    pks = parseWalletPub(a, wallet)
    cts = []
    for i in range(len(messages)):
        msg = messages[i]
        bf = policies[i]
        if a.scheme_type == "maabe":
            pk_list = []
            for auth in pks:
                pk_list.append(pks[auth])
            ct = a.Encrypt(msg,
                           bf,
                           pk_list)
        elif a.scheme_type == "fame":
            ct = a.Encrypt(msg,
                       bf,
                       pks)

        if ct is None:
            print("Could not encrypt")
            return
        cts.append(ct)

    ret = a.Sign(cts, sigWallet, proof)
    print("\n* Encrypted and signed messages:\n")
    print(ret)
    print("")

    return ret

def verifyAndDecrypt(a, cipher, walletK, uuid, walletPk = None, ca=None):
    ks = parseWalletSec(a, walletK)
    if a.scheme_type == "maabe":
        pt = a.VerifyAndDecrypt(cipher,
                            ks,
                            None,
                            uuid)
    if a.scheme_type == "fame":
        pk = parseWalletPub(a, walletPk)
        if ca != None:
            with open(ca) as o:
                ca = o.read()
        pt = a.VerifyAndDecrypt(cipher,
                                ks,
                                pk,
                                uuid,
                                ca)
    if pt is None:
        print("Could not decrypt")
        return

    print("\n* Verified and decrypted the messages:\n")
    print(pt)
    print("")
    print("")

    return pt
