import hashlib
import unittest

import ctypes
import random
import os

from src.ahe_bindings.ahe_bindings import Ahe, MasterKeys, CHARPP
from src.ahe_bindings.ahe_types import \
        Maabe,\
        MaabeAuth,\
        MaabePubKey,\
        MaabeSecKey,\
        MaabeCipher,\
        MaabeKey
from src.ahe_bindings.ahe_exceptions import \
        AheEmptyMessage,\
        AheEmptyDecryptionPolicy,\
        AheEmptyGid,\
        AheEmptyAttribute,\
        AheEmptyAttributeList,\
        AheEmptyPublicKey,\
        AheEmptyPublicKeyList,\
        AheEmptyID,\
        AheEmptyScheme,\
        AheEmptyMaabeAuth,\
        AheEmptyCipher,\
        AheEmptyKey,\
        AheEmptyKeyList,\
        AheTypeConversionError,\
        AheOperationOnEmptyObject, \
        AheVerificationError


class TestAhe(unittest.TestCase):
    """This class contains all tests for ahe_bindings. It extends
    :class:`unittest.TestCase`. Any arguments are merely passed to the super's
    constructor.
    """

    def __init__(self, *args):
        """Test object constructor.
        """
        super().__init__(*args)
        script_dir = os.path.dirname(__file__)
        ahe_path = os.path.join(script_dir, "../../prebuild/linux-x86-64/libahe.so")
        # ahe_path = os.path.join(script_dir, "../../build/libahe.so")
        self.g = Ahe(ahe_path)

    def test_ahe_lifecycle(self):
        """Test the lifecycle of the encryption scheme.
        """
        script_dir = os.path.dirname(__file__)
        ahe_path = os.path.join(script_dir, "../../prebuild/linux-x86-64/libahe.so")
        # ahe_path = os.path.join(script_dir, "../../build/libahe.so")
        g = Ahe(ahe_path)

        """Test maabe scheme"""
        g.SetScheme("maabe")

        # construct new authorities
        auth1 = g.NewMaabeAuth("auth1", ["auth1:at1", "auth1:at2"])
        auth2 = g.NewMaabeAuth("auth2", ["auth2:at1", "auth2:at2"])
        auth3 = g.NewMaabeAuth("auth3", ["auth3:at1", "auth3:at2"])
        # collect their pubkeys
        pks = [auth1.Pk, auth2.Pk, auth3.Pk]
        # encrypt a message with a decryption policy
        msg = "Attack at dawn!"
        bf = "((auth1:at1 AND auth2:at1) OR "\
             "(auth1:at2 AND auth2:at2)) OR "\
             "(auth3:at1 AND auth3:at2)"
        enc = g.Encrypt(msg, bf, pks)
        bf2 = "auth1:at1 AND auth2:at2"
        enc2 = g.Encrypt(msg, bf2, pks)
        verKey = g.GenerateSigningKeys()
        enc_signed = g.Sign([enc, enc2])
        check = g.Verify(enc_signed)
        self.assertEqual(check, True)

        enc_list = g.CiphersFromJSON(enc_signed)
        self.assertIsNotNone(enc_list)

        # get attribute keys for a user
        gid = "gid1"
        keys1 = g.GenAttribKeys(auth1, ["auth1:at1", "auth1:at2"], gid)
        keys2 = g.GenAttribKeys(auth2, ["auth2:at1", "auth2:at2"], gid)
        keys3 = g.GenAttribKeys(auth3, ["auth3:at1", "auth3:at2"], gid)
        # combine keys
        ks1 = [keys1[0], keys2[0], keys3[0]]
        ks2 = [keys1[1], keys2[1], keys3[1]]
        ks3 = [keys1[0], keys2[1]]
        ks4 = [keys1[1], keys2[0]]
        ks5 = [keys3[0], keys3[1]]
        pt1 = g.Decrypt(enc, ks1)  # returns msg
        self.assertEqual(msg, pt1)
        pt2 = g.Decrypt(enc, ks2)  # returns msg
        self.assertEqual(msg, pt2)
        pt3 = g.Decrypt(enc, ks3)  # fails with None
        self.assertIsNone(pt3)
        pt4 = g.Decrypt(enc, ks4)  # fails with None
        self.assertIsNone(pt4)
        pt5 = g.Decrypt(enc, ks5)  # returns msg
        self.assertEqual(msg, pt5)

        pts = g.VerifyAndDecrypt(enc_signed, ks1)
        self.assertEqual(pts[0], msg)
        self.assertEqual(pts[1], None)

        """Test fame scheme"""
        g.SetScheme("fame")
        pk, sk = g.NewFameGenerateMasterKeys()
        bf3 = "at1 AND at2"
        enc3 = g.Encrypt(msg, bf3, pk)
        keys4 = g.GenAttribKeys(sk, ["at1", "at2", "at3"])
        dec = g.Decrypt(enc3, keys4, pk)
        self.assertEqual(dec, msg)

        bf4 = "(at2 AND at4) OR at5"
        enc4 = g.Encrypt(msg, bf4, pk)
        verKey2 = g.GenerateSigningKeys()
        enc_signed2 = g.Sign([enc4])
        try:
            check = False
            check = g.Verify(enc_signed2)
        except AheVerificationError:
            self.assertEqual(check, False)

        check = g.Verify(enc_signed2)
        self.assertEqual(check, True)

        enc_signed3 = g.Sign([enc3, enc4])

        dec3 = g.VerifyAndDecrypt(enc_signed3, keys4, pk)
        self.assertEqual(dec3[0], msg)
        self.assertEqual(dec3[1], None)


    def test_ahe_char_to_str_conversion(self):
        """Test the conversion str -> char * -> str.
        """
        random.seed()
        word = str(random.randrange(1000, 1000000))
        charp = Ahe.python_str_to_c_charp(word)
        wordNew = Ahe.c_charp_to_python_str(charp)
        self.assertEqual(word, wordNew)

    def test_ahe_char_to_strlist_conversion(self):
        """Test the conversion List[str] -> char ** -> List[str].
        """
        random.seed()
        n = random.randrange(50) + 1
        strList = []
        for i in range(n):
            strList.append(str(random.randrange(1000, 1000000)))
        charpp = Ahe.python_strlist_to_c_charpp(strList)
        strListNew = Ahe.c_charpp_to_python_strlist(charpp, n)
        self.assertListEqual(strList, strListNew)

    def test_ahe_char_to_strlist_utf(self):
        """Test that the conversion char ** -> List[str] fails when fed
        degenerate data.
        """
        # example of a byte array that cannot be decoded w.r.t. utf-8
        byteList = [b'AB\xfc', u'æ'.encode('cp1252')]
        charpp = (ctypes.c_char_p * len(byteList))()
        charpp[:] = byteList
        self.assertRaises(UnicodeDecodeError,
                          Ahe.c_charpp_to_python_strlist,
                          byteList,
                          2)

    def test_ahe_strlist_to_char_utf(self):
        """Test that the conversion List[str] -> char ** fails when fed
        degenerate data.
        """
        # example of a str array that cannot be encoded w.r.t. utf-8
        strList = ['\ud861\udd37']
        self.assertRaises(UnicodeEncodeError,
                          Ahe.python_strlist_to_c_charpp,
                          strList)

    def test_ahe_char_to_strlist_empty_arg(self):
        """Test conversion fail on bad args char ** -> List[str]
        """
        byteList = [b'abc', b'123']
        charpp = (ctypes.c_char_p * len(byteList))()
        charpp[:] = byteList
        self.assertRaises(AheTypeConversionError,
                          Ahe.c_charpp_to_python_strlist,
                          None,
                          1)
        self.assertRaises(AheTypeConversionError,
                          Ahe.c_charpp_to_python_strlist,
                          charpp,
                          0)
        self.assertRaises(AheTypeConversionError,
                          Ahe.c_charpp_to_python_strlist,
                          charpp,
                          -42)

    def test_ahe_strlist_to_char_empty_arg(self):
        """Test conversion fail on bad args List[str] -> char **
        """
        strListEmpty = []
        strListEmptyEnt = ["lol", ""]
        self.assertRaises(AheTypeConversionError,
                          Ahe.python_strlist_to_c_charpp,
                          strListEmpty)
        self.assertRaises(AheTypeConversionError,
                          Ahe.python_strlist_to_c_charpp,
                          strListEmptyEnt)

    def test_ahe_newmaabe_len(self):
        """Test maabe is the correct length.
        """
        maabe = self.g.NewMaabe()
        maabeList = maabe.toStringList()
        self.assertEqual(len(maabeList),
                         4)

    def test_ahe_newauth_len(self):
        """Test maabe auth is the correct length.
        """
        self.g.SetScheme("maabe")
        random.seed()
        n = random.randrange(50) + 1
        attribs = []
        for i in range(n):
            attribs.append("id:at" + str(i))
        auth = self.g.NewMaabeAuth("id",
                                   attribs)
        authList = auth.toStringList()
        self.assertEqual(len(authList),
                         5 + 5*n)

    def test_ahe_newauth_utf(self):
        """Test maabe auth fails on degenerate string entries.
        """
        strList = ['\ud861\udd37']
        ID = strList[0]
        self.g.SetScheme("maabe")
        attribs = ["at1", "at2"]
        self.assertRaises(UnicodeEncodeError,
                          self.g.NewMaabeAuth,
                          ID,
                          attribs)
        ID = "id"
        attribs = strList
        self.assertRaises(UnicodeEncodeError,
                          self.g.NewMaabeAuth,
                          ID,
                          attribs)

    def test_ahe_newauth_empty_arg(self):
        """Test maabe auth fails on degenerate string entries.
        """
        self.g.SetScheme("maabe")
        ID = "id"
        IDEmpty = ""
        attribs = ["at1", "at2"]
        attribsEmpty = []
        attribsEmptyEnt = ["", "at2"]
        self.assertRaises(AheEmptyID,
                          self.g.NewMaabeAuth,
                          IDEmpty,
                          attribs)
        self.assertRaises(AheEmptyAttributeList,
                          self.g.NewMaabeAuth,
                          ID,
                          attribsEmpty)
        self.assertRaises(AheEmptyAttribute,
                          self.g.NewMaabeAuth,
                          ID,
                          attribsEmptyEnt)

    def test_ahe_encrypt_cipher_len(self):
        """Test maabe ciphertext is the correct length.
        """
        self.g.SetScheme("maabe")
        random.seed()
        n = random.randrange(2, 50) + 1
        attribs = []
        for i in range(n):
            attribs.append("id:at" + str(i))
        auth = self.g.NewMaabeAuth("id",
                                   attribs)
        msg = "Attack at dawn!" + str(n)
        bf = "(id:at0 AND id:at1)"
        i = 2
        while i < n:
            if i + 1 < n:
                bf += " OR (id:at{} AND id:at{})".format(str(i),
                                                         str(i+1))
                i += 2
            else:
                bf += " OR id:at{}".format(str(i))
                i += 1
        enc = self.g.Encrypt(msg,
                                  bf,
                                  [auth.Pk])
        encList = enc.toStringList()
        self.assertEqual(len(encList),
                         6 + 4 * n)

    def test_ahe_encrypt_utf(self):
        """Test maabe encrypt fails on degenerate string entries.
        """
        deg = '\ud861\udd37'
        ID = "id"
        self.g.SetScheme("maabe")
        attribs = ["at1", "at2"]
        auth = self.g.NewMaabeAuth(ID,
                                   attribs)
        msg = deg
        bf = "at1 AND at2"
        self.assertRaises(UnicodeEncodeError,
                          self.g.Encrypt,
                          msg,
                          bf,
                          [auth.Pk])
        msg = "Attack at dawn!"
        bf = "at1 AND at{}".format(deg)
        self.assertRaises(UnicodeEncodeError,
                          self.g.Encrypt,
                          msg,
                          bf,
                          [auth.Pk])

    def test_ahe_encrypt_empty_arg(self):
        """Test Encrypt fails on empty string entry.
        """
        self.g.SetScheme("maabe")
        ID = "id"
        attribs = ["at1", "at2"]
        auth = self.g.NewMaabeAuth(ID,
                                   attribs)
        maabeEmpty = Maabe()
        msg = "Attack at dawn!"
        msgEmpty = ""
        bf = "at1 AND at2"
        bfEmpty = ""
        pks = [auth.Pk]
        pksEmpty = []
        pksEmptyEnt = [MaabePubKey()]
        self.assertRaises(AheEmptyScheme,
                          self.g.EncryptMaabe,
                          maabeEmpty,
                          msg,
                          bf,
                          pks)
        self.assertRaises(AheEmptyMessage,
                          self.g.Encrypt,
                          msgEmpty,
                          bf,
                          pks)
        self.assertRaises(AheEmptyDecryptionPolicy,
                          self.g.Encrypt,
                          msg,
                          bfEmpty,
                          pks)
        self.assertRaises(AheEmptyPublicKeyList,
                          self.g.Encrypt,
                          msg,
                          bf,
                          pksEmpty)
        self.assertRaises(AheEmptyPublicKey,
                          self.g.Encrypt,
                          msg,
                          bf,
                          pksEmptyEnt)

    def test_ahe_genkey_len(self):
        """Test GenAttribKeys is the correct length.
        """
        self.g.SetScheme("maabe")
        ID = "id"
        random.seed()
        n = random.randrange(2, 50) + 1
        attribs = []
        for i in range(n):
            attribs.append("id:at" + str(i))
        auth = self.g.NewMaabeAuth(ID,
                                   attribs)
        gid = "gid"
        keys = self.g.GenMaabeAttribKeys(auth,
                                    gid,
                                    attribs)
        self.assertEqual(len(keys),
                         n)
        for k in keys:
            self.assertEqual(len(k.toStringList()),
                             3)

    def test_ahe_genkey_utf(self):
        """Test GenAttribKeys fails on degenerate string entry.
        """
        deg = '\ud861\udd37'
        self.g.SetScheme("maabe")
        ID = "id"
        attribs = ["at1", "at2"]
        auth = self.g.NewMaabeAuth(ID,
                                   attribs)
        gid = deg
        self.assertRaises(UnicodeEncodeError,
                          self.g.GenMaabeAttribKeys,
                          auth,
                          gid,
                          attribs)

    def test_ahe_genkey_empty_arg(self):
        """Test GenAttribKeys fails on empty string entry.
        """
        self.g.SetScheme("maabe")
        ID = "id"
        attribs = ["at1", "at2"]
        attribsEmpty = []
        attribsEmptyEnt = ["at1", ""]
        auth = self.g.NewMaabeAuth(ID,
                                   attribs)
        authEmpty = MaabeAuth()
        gid = "gid"
        gidEmpty = ''
        self.assertRaises(AheEmptyMaabeAuth,
                          self.g.GenMaabeAttribKeys,
                          authEmpty,
                          gid,
                          attribs)
        self.assertRaises(AheEmptyGid,
                          self.g.GenMaabeAttribKeys,
                          auth,
                          gidEmpty,
                          attribs)
        self.assertRaises(AheEmptyAttributeList,
                          self.g.GenMaabeAttribKeys,
                          auth,
                          gid,
                          attribsEmpty)
        self.assertRaises(AheEmptyAttribute,
                          self.g.GenMaabeAttribKeys,
                          auth,
                          gid,
                          attribsEmptyEnt)

    def test_ahe_decrypt_empty_arg(self):
        """Test Decrypt fails on empty args.
        """
        self.g.SetScheme("maabe")
        ID = "id"
        attribs = ["at1", "at2"]
        auth = self.g.NewMaabeAuth(ID,
                                   attribs)
        msg = "Attack at dawn!"
        bf = "at1 AND at2"
        pks = [auth.Pk]
        ct = self.g.Encrypt(msg,
                                 bf,
                                 pks)
        ctEmpty = MaabeCipher()
        ks = self.g.GenMaabeAttribKeys(auth,
                                  "gid",
                                  attribs)
        ksEmpty = []
        ksEmptyEnt = [ks[0], MaabeKey()]
        self.assertRaises(AheEmptyCipher,
                          self.g.Decrypt,
                          ctEmpty,
                          ks)
        self.assertRaises(AheEmptyKeyList,
                          self.g.Decrypt,
                          ct,
                          ksEmpty)
        self.assertRaises(AheEmptyKey,
                          self.g.Decrypt,
                          ct,
                          ksEmptyEnt)

    def test_ahe_empty_objects(self):
        """Test if methods on empty objects fail.
        """
        maabe = Maabe()
        auth = MaabeAuth()
        pk = MaabePubKey()
        sk = MaabeSecKey()
        ct = MaabeCipher()
        k = MaabeKey()
        self.assertRaises(AheOperationOnEmptyObject,
                          maabe.toStringList)
        self.assertRaises(AheOperationOnEmptyObject,
                          auth.toStringList)
        self.assertRaises(AheOperationOnEmptyObject,
                          pk.toStringList)
        self.assertRaises(AheOperationOnEmptyObject,
                          sk.toStringList)
        self.assertRaises(AheOperationOnEmptyObject,
                          ct.toStringList)
        self.assertRaises(AheOperationOnEmptyObject,
                          ct.sha256sum)
        self.assertRaises(AheOperationOnEmptyObject,
                          k.toStringList)

    def test_ahe_json_pk(self):
        """Test whether the json bindings for MaabePubKey are working
        correctly.
        """
        self.g.SetScheme("maabe")
        auth = self.g.NewMaabeAuth("auth",
                                   ["auth:at1", "auth:at2"])
        pkJSON = self.g.PubKeyToJSON(auth.Pk)
        self.assertIsNotNone(pkJSON)
        pkNew = self.g.PubKeyFromJSON(pkJSON)
        self.assertEqual(auth.Pk.attrib,
                         pkNew.attrib)
        self.assertEqual(auth.Pk.eggToAlpha,
                         pkNew.eggToAlpha)
        self.assertEqual(auth.Pk.gToY,
                         pkNew.gToY)
        pkNewJSON = self.g.PubKeyToJSON(pkNew)
        self.assertIsNotNone(pkNewJSON)

    def test_ahe_json_ct(self):
        """Test whether the json bindings for MaabeCipher are working
        correctly.
        """
        self.g.SetScheme("maabe")
        auth = self.g.NewMaabeAuth("auth",
                                   ["auth:at1", "auth:at2"])
        msg = "Attack at dawn!"
        bf = "(auth:at1 AND auth:at2)"
        ct = self.g.Encrypt(msg,
                                 bf,
                                 [auth.Pk])
        self.assertIsNotNone(ct)
        ctJSON = self.g.CiphersToJSON([ct])
        self.assertIsNotNone(ctJSON)
        ctNew = self.g.CiphersFromJSON(ctJSON)[0]
        self.assertIsNotNone(ctNew)
        self.assertEqual(ct.SymEnc,
                         ctNew.SymEnc)
        self.assertEqual(ct.Iv,
                         ctNew.Iv)
        self.assertEqual(ct.MSP_Mat,
                         ctNew.MSP_Mat)
        self.assertEqual(ct.MSP_RowToAttrib,
                         ctNew.MSP_RowToAttrib)
        self.assertEqual(ct.C0,
                         ctNew.C0)
        self.assertEqual(ct.attrib.sort(),
                         ctNew.attrib.sort())
        self.assertEqual(list(zip(ct.attrib,
                                  ct.C1)).sort(key=lambda x: x[0]),
                         list(zip(ct.attrib,
                                  ctNew.C1)).sort(key=lambda x: x[0]))
        self.assertEqual(list(zip(ct.attrib,
                                  ct.C2)).sort(key=lambda x: x[0]),
                         list(zip(ct.attrib,
                                  ctNew.C2)).sort(key=lambda x: x[0]))
        self.assertEqual(list(zip(ct.attrib,
                                  ct.C3)).sort(key=lambda x: x[0]),
                         list(zip(ct.attrib,
                                  ctNew.C3)).sort(key=lambda x: x[0]))
        ctNewJSON = self.g.CiphersToJSON([ctNew])
        self.assertIsNotNone(ctNewJSON)

    def test_ahe_json_ks(self):
        """Test whether the json bindings for MaabeKey are working correctly.
        """
        self.g.SetScheme("maabe")
        auth = self.g.NewMaabeAuth("auth",
                                   ["auth:at1", "auth:at2"])
        ks = self.g.GenMaabeAttribKeys(auth,
                                  "user",
                                  ["auth:at1", "auth:at2"])
        ksJSON = self.g.AttributeKeysToJSON(ks)
        self.assertIsNotNone(ksJSON)
        ksNew = self.g.AttributeKeysFromJSON(ksJSON)
        for i in range(len(ks)):
            self.assertEqual(ks[i].Gid,
                             ksNew[i].Gid)
            self.assertEqual(ks[i].Attrib,
                             ksNew[i].Attrib)
            self.assertEqual(ks[i].Key,
                             ksNew[i].Key)
        ksNewJSON = self.g.AttributeKeysToJSON(ksNew)
        self.assertIsNotNone(ksNewJSON)


if __name__ == '__main__':
    unittest.main()
