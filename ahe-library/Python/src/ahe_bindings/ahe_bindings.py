from typing import List, Union
import ctypes
import json
import os


from .ahe_types import \
        Maabe,\
        MaabeAuth,\
        MaabePubKey,\
        MaabeCipher,\
        MaabeKey, \
        Fame, \
        FamePubKey, \
        FameSecKey, \
        FameCipher, \
        FameKey

from .ahe_exceptions import \
        AheEmptyMessage,\
        AheEmptyDecryptionPolicy,\
        AheEmptyGid,\
        AheEmptyAttribute,\
        AheEmptyAttributeList,\
        AheEmptyPublicKey,\
        AheEmptyPublicKeyList,\
        AheEmptyID,\
        AheEmptyScheme,\
        AheEmptyMaabeAuth, \
        AheEmptyCipher,\
        AheEmptyKey,\
        AheEmptyKeyList,\
        AheTypeConversionError,\
        AheVerificationError, \
        AheSchemeError

LIB_AHE = "../../../build/libahe.so"
CHARPP = ctypes.POINTER(ctypes.c_char_p)

class StringList(ctypes.Structure):
    """The StringList class represents a list of strings as passed by C
    functions. It extends :class:`ctypes.Structure`.

    It contains the following information:
        data    -   char ** pointing to the first string in the list
        length  -   the length of the string list
    """
    _fields_ = [('data', ctypes.POINTER(ctypes.c_char_p)),
                ('length', ctypes.c_int)]

class MasterKeys(ctypes.Structure):
    """The StringList class represents a list of strings as passed by C
    functions. It extends :class:`ctypes.Structure`.

    It contains the following information:
        data    -   char ** pointing to the first string in the list
        length  -   the length of the string list
    """
    _fields_ = [('pk', ctypes.c_char_p),
                ('sk', ctypes.c_char_p)]

class Ahe:
    """The Ahe class provides a Python interface for libahe.so. Its purpose
    is to load the shared library, obtain handles to all the functions, and
    wrap them in functions using Python types (which are then provided as
    methods of this class).

    :param ahe_path:    the file system path to the libahe.so shared library,
                        defaults to ''
    :type ahe_path:     str
    """

    def __init__(self,
                 ahe_path: str = ""
                 ) -> None:
        """The constructor of the Ahe class.
        """
        libahe: str = LIB_AHE
        if ahe_path:
            libahe = ahe_path
        # load the library
        ahe = ctypes.CDLL(libahe)
        # establish functions
        self.scheme_type = ""
        self.scheme = None

        # functions that Ahe imports

        # maabe functions
        self.new_maabe = ahe.Ahe_maabe_NewMAABE
        self.new_maabe.restype = ctypes.POINTER(ctypes.c_char_p)
        # new_auth
        self.new_maabe_auth = ahe.Ahe_maabe_NewMAABEAuth
        self.new_maabe_auth.restype = StringList
        # encrypt
        self.maabe_encrypt = ahe.Ahe_maabe_Encrypt
        self.maabe_encrypt.restype = StringList
        # gen_keys
        self.maabe_gen_keys = ahe.Ahe_maabe_GenerateAttribKeys
        self.maabe_gen_keys.restype = StringList
        # decrypt
        self.maabe_decrypt = ahe.Ahe_maabe_Decrypt
        self.maabe_decrypt.restype = ctypes.c_char_p
        # pubkey json
        self.maabe_pk_to_json = ahe.Ahe_maabe_PubKeyToJSON
        self.maabe_pk_to_json.restype = ctypes.c_char_p
        self.maabe_pk_from_json = ahe.Ahe_maabe_PubKeyFromJSON
        self.maabe_pk_from_json.restype = StringList
        # attrib key json
        self.maabe_ks_to_json = ahe.Ahe_maabe_AttribKeysToJSON
        self.maabe_ks_to_json.restype = ctypes.c_char_p
        self.maabe_ks_from_json = ahe.Ahe_maabe_AttribKeysFromJSON
        self.maabe_ks_from_json.restype = StringList
        # cipher json
        # self.maabe_ct_to_json = ahe.Ahe_maabe_CipherToJSON
        # self.maabe_ct_to_json.restype = ctypes.c_char_p
        # self.maabe_ct_from_json = ahe.Ahe_maabe_CipherFromJSON
        # self.maabe_ct_from_json.restype = StringList

        # fame functions
        self.new_fame = ahe.Ahe_fame_NewFAME
        self.new_fame.restype = ctypes.c_char_p
        self.new_fame_generate_master_keys = ahe.Ahe_fame_GenerateMasterKeys
        self.new_fame_generate_master_keys.restype = MasterKeys
        # encrypt
        self.fame_encrypt = ahe.Ahe_fame_Encrypt
        self.fame_encrypt.restype = StringList
        # gen_keys
        self.fame_gen_keys = ahe.Ahe_fame_GenerateAttribKeys
        self.fame_gen_keys.restype = StringList
        # # decrypt
        self.fame_decrypt = ahe.Ahe_fame_Decrypt
        self.fame_decrypt.restype = ctypes.c_char_p
        # decentralized attribute keys
        self.fame_decrypt_keys = ahe.Ahe_fame_decrytAttribKeys
        self.fame_decrypt_keys.restype = StringList
        self.fame_join_dec_keys = ahe.Ahe_fame_joinDecAttribKeys
        self.fame_join_dec_keys.restype = StringList
        # signature functions
        self.sig_generate_keys = ahe.Ahe_GenerateSigKeys
        self.sig_generate_keys.restype = MasterKeys
        self.sig_sign_ciphers = ahe.Ahe_SignCiphers
        self.sig_sign_ciphers.restype = ctypes.c_char_p
        self.sig_verify_sig = ahe.Ahe_VerifySig
        self.sig_verify_sig.restype = int


    def SetScheme(self, scheme_type: str = "fame") -> None:
        if scheme_type not in ["maabe", "fame"]:
            raise AheSchemeError

        self.scheme_type: str = scheme_type

        if scheme_type == "maabe":
            maabeC: CHARPP = self.new_maabe()
            maabeStrList: List[str] = Ahe.c_charpp_to_python_strlist(maabeC, 4)
            self.scheme = Maabe(maabeStrList)

        elif scheme_type == "fame":
            fameC: ctypes.c_char_p = self.new_fame()
            fameStr: str = Ahe.c_charp_to_python_str(fameC)
            self.scheme = Fame(fameStr)



    def NewMaabe(self) -> Maabe:
        """Wrapper function for libahe's Ahe_maabe_NewMAABE.

        :return:    a new Maabe object encapsulating the public parameters
        :rtype:     :class:`Maabe`
        """
        maabeC: CHARPP = self.new_maabe()
        maabeStrList: List[str] = Ahe.c_charpp_to_python_strlist(maabeC, 4)
        return Maabe(maabeStrList)

    def NewMaabeAuth(self,
                     ID: str,
                     attribs: List[str]
                     ) -> MaabeAuth:
        """Wrapper function for libahe's Ahe_maabe_NewMAABEAuth.

        :param maabe:                   the public parameters
        :type maabe:                    :class:`Maabe`
        :param ID:                      a string ID of the authority
        :type ID:                       str
        :param attribs:                 a list of attributes managed by this
                                        authority
        :type attribs:                  list[str]
        :return:                        a new MaabeAuth object encapsulating
                                        and single authority
        :rtype:                         :class:`MaabeAuth`
        :raises AheEmptyScheme:          empty Maabe() object passed
        :raises AheEmptyID:             empty ID string passed
        :raises AheEmptyAttributeList:  empty attribs list passed
        :raises AheEmptyAttribute:      the attribs list contains an empty
                                        attribute
        """
        if not ID:
            raise(AheEmptyID)
        if not attribs:
            raise(AheEmptyAttributeList)
        for at in attribs:
            if not at:
                raise(AheEmptyAttribute)
        maabeStrList: List[str] = self.scheme.toStringList()
        maabeC: CHARPP = Ahe.python_strlist_to_c_charpp(maabeStrList)
        idC: ctypes.c_char_p = ctypes.c_char_p(ID.encode('utf-8',
                                                         'strict'))
        attribsC: CHARPP = Ahe.python_strlist_to_c_charpp(attribs)
        authC: StringList = self.new_maabe_auth(maabeC, idC, attribsC, len(attribs))
        authDataList: List[str] = Ahe.c_charpp_to_python_strlist(authC.data,
                                                                 authC.length)
        return MaabeAuth(authDataList)

    def NewFameGenerateMasterKeys(self
                                  ) -> (FamePubKey, FameSecKey):

        if self.scheme.isEmpty():
            raise(AheEmptyScheme)

        keys: MasterKeys = self.new_fame_generate_master_keys(Ahe.python_str_to_c_charp(self.scheme.toString()))

        return FamePubKey(Ahe.c_charp_to_python_str(keys.pk)), FameSecKey(Ahe.c_charp_to_python_str(keys.sk))

    def Encrypt(self,
                 msg: str,
                 bf: str,
                 pks: Union[List[MaabePubKey], FamePubKey]
                 ) -> Union[MaabeCipher, FameCipher]:
        """Wrapper function for libahe's encryption functions.

        :param msg:                         a string ID of the authority
        :type msg:                          str
        :param bf:                          a string boolean formula
                                            representing the decryption policy
        :type bf:                           str
        :param pks:                         a list of public keys of the
                                            authorities involved in the
                                            decryption policy
        :type pks:                          list[:class:`MaabePubKey`]
        :return:                            a new MaabeCipher object
                                            encapsulating a ciphertext
        :rtype:                             :class:`MaabeCipher`
        :raises AheEmptyScheme:              empty Maabe() object passed
        :raises AheEmptyMessage:            empty message string passed
        :raises AheEmptyDecryptionPolicy:   empty boolean formula passed
        :raises AheEmptyPublicKeyList:      empty pubkey list passed
        :raises AheEmptyPublicKey:          the pubkey list contains an empty
                                            pubkey
        """
        if self.scheme_type == "maabe":
            res = self.EncryptMaabe(self.scheme, msg, bf, pks)
            return res
        if self.scheme_type == "fame":
            res = self.EncryptFame(self.scheme, msg, bf, pks)
            return res


    def EncryptMaabe(self,
                     maabe: Maabe,
                     msg: str,
                     bf: str,
                     pks: List[MaabePubKey]
                     ) -> MaabeCipher:
        """Wrapper function for libahe's Ahe_maabe_Encrypt.

        :param maabe:                       the public parameters
        :type maabe:                        :class:`Maabe`
        :param msg:                         a string ID of the authority
        :type msg:                          str
        :param bf:                          a string boolean formula
                                            representing the decryption policy
        :type bf:                           str
        :param pks:                         a list of public keys of the
                                            authorities involved in the
                                            decryption policy
        :type pks:                          list[:class:`MaabePubKey`]
        :return:                            a new MaabeCipher object
                                            encapsulating a ciphertext
        :rtype:                             :class:`MaabeCipher`
        :raises AheEmptyScheme:              empty Maabe() object passed
        :raises AheEmptyMessage:            empty message string passed
        :raises AheEmptyDecryptionPolicy:   empty boolean formula passed
        :raises AheEmptyPublicKeyList:      empty pubkey list passed
        :raises AheEmptyPublicKey:          the pubkey list contains an empty
                                            pubkey
        """
        if maabe.isEmpty():
            raise(AheEmptyScheme)
        if not msg:
            raise(AheEmptyMessage)
        if not bf:
            raise(AheEmptyDecryptionPolicy)
        if not pks:
            raise(AheEmptyPublicKeyList)
        for pk in pks:
            if pk.isEmpty():
                raise(AheEmptyPublicKey)
        maabeStrList: List[str] = maabe.toStringList()
        maabeC: CHARPP = Ahe.python_strlist_to_c_charpp(maabeStrList)
        msgC: ctypes.c_char_p = ctypes.c_char_p(msg.encode('utf-8',
                                                           'strict'))
        bfC: ctypes.c_char_p = ctypes.c_char_p(bf.encode('utf-8',
                                                         'strict'))
        pksStrList: List[str] = []
        for pk in pks:
            pksStrList += pk.toStringList()
        pksC: CHARPP = Ahe.python_strlist_to_c_charpp(pksStrList)
        encC: StringList = self.maabe_encrypt(maabeC,
                                              msgC,
                                              bfC,
                                              pksC,
                                              len(pksStrList))
        encDataList: List[str] = Ahe.c_charpp_to_python_strlist(encC.data,
                                                                encC.length)
        return MaabeCipher(encDataList)

    def EncryptFame(self,
                         fame: Fame,
                         msg: str,
                         bf: str,
                         pks: FamePubKey
                         ) -> FameCipher:
        """Wrapper function for libahe's Ahe_maabe_Encrypt.

        :param maabe:                       the public parameters
        :type maabe:                        :class:`Maabe`
        :param msg:                         a string ID of the authority
        :type msg:                          str
        :param bf:                          a string boolean formula
                                            representing the decryption policy
        :type bf:                           str
        :param pks:                         a list of public keys of the
                                            authorities involved in the
                                            decryption policy
        :type pks:                          list[:class:`MaabePubKey`]
        :return:                            a new MaabeCipher object
                                            encapsulating a ciphertext
        :rtype:                             :class:`MaabeCipher`
        :raises AheEmptyScheme:              empty Maabe() object passed
        :raises AheEmptyMessage:            empty message string passed
        :raises AheEmptyDecryptionPolicy:   empty boolean formula passed
        :raises AheEmptyPublicKeyList:      empty pubkey list passed
        :raises AheEmptyPublicKey:          the pubkey list contains an empty
                                            pubkey
        """
        if fame.isEmpty():
            raise(AheEmptyScheme)
        if not msg:
            raise(AheEmptyMessage)
        if not bf:
            raise(AheEmptyDecryptionPolicy)
        if not pks:
            raise(AheEmptyPublicKeyList)
        if pks.isEmpty():
            raise(AheEmptyPublicKey)
        maabeStr: str = fame.toString()
        maabeC: ctypes.c_char_p = Ahe.python_str_to_c_charp(maabeStr)
        msgC: ctypes.c_char_p = ctypes.c_char_p(msg.encode('utf-8',
                                                           'strict'))
        bfC: ctypes.c_char_p = ctypes.c_char_p(bf.encode('utf-8',
                                                         'strict'))
        pksStr: str = pks.toString()
        pksC: ctypes.c_char_p = Ahe.python_str_to_c_charp(pksStr)
        encC: StringList = self.fame_encrypt(maabeC,
                                              msgC,
                                              bfC,
                                              pksC,
                                              pksStr)
        encDataList: List[str] = Ahe.c_charpp_to_python_strlist(encC.data,
                                                                encC.length)
        return FameCipher(encDataList)

    def GenAttribKeys(self,
                      auth: Union[MaabeAuth, FameSecKey],
                      attribs: List[str],
                      gid: str = "",
                      ) -> Union[List[MaabeKey], List[FameKey], None]:
        """Wrapper function for libahe's Ahe_maabe_GenerateAttribKeys.

        :param auth:                    the authority generating the keys
        :type auth:                     :class:`MaabeAuth`
        :param gid:                     a string global id for the user
        :type gid:                      str
        :param attribs:                 a list of attributes the user wants
                                        keys for
        :type attribs:                  list[str]
        :return:                        a list of MaabeKey objects
                                        encapsulating single keys
        :rtype:                         list[:class:`MaabeKey`]
        :raises AheEmptyMaabeAuth:      empty MaabeAuth() object passed
        :raises AheEmptyGid:            empty GID string passed
        :raises AheEmptyAttributeList:  empty attribs list passed
        :raises AheEmptyAttribute:      the attribs list contains an empty
                                        attribute
        """
        if self.scheme_type == "maabe":
            res = self.GenMaabeAttribKeys(auth, gid, attribs)
            return res

        if self.scheme_type == "fame":
            res = self.GenFameAttribKeys(auth, attribs)
            return res


    def GenMaabeAttribKeys(self,
                      auth: MaabeAuth,
                      gid: str,
                      attribs: List[str]
                      ) -> Union[List[MaabeKey], None]:
        """Wrapper function for libahe's Ahe_maabe_GenerateAttribKeys.

        :param auth:                    the authority generating the keys
        :type auth:                     :class:`MaabeAuth`
        :param gid:                     a string global id for the user
        :type gid:                      str
        :param attribs:                 a list of attributes the user wants
                                        keys for
        :type attribs:                  list[str]
        :return:                        a list of MaabeKey objects
                                        encapsulating single keys
        :rtype:                         list[:class:`MaabeKey`]
        :raises AheEmptyMaabeAuth:      empty MaabeAuth() object passed
        :raises AheEmptyGid:            empty GID string passed
        :raises AheEmptyAttributeList:  empty attribs list passed
        :raises AheEmptyAttribute:      the attribs list contains an empty
                                        attribute
        """
        if auth.isEmpty():
            raise(AheEmptyMaabeAuth)
        if not gid:
            raise(AheEmptyGid)
        if not attribs:
            raise(AheEmptyAttributeList)
        for at in attribs:
            if not at:
                raise(AheEmptyAttribute)
        authStrList: List[str] = auth.toStringList()
        authC: CHARPP = Ahe.python_strlist_to_c_charpp(authStrList)
        gidC: ctypes.c_char_p = ctypes.c_char_p(gid.encode('utf-8',
                                                           'strict'))
        attribsC: CHARPP = Ahe.python_strlist_to_c_charpp(attribs)
        keysC: StringList = self.maabe_gen_keys(authC,
                                                len(authStrList),
                                                gidC, attribsC,
                                                len(attribs))
        keysDataList: List[str] = Ahe.c_charpp_to_python_strlist(keysC.data,
                                                                 keysC.length)
        if len(keysDataList) % 3 != 0:
            return None
        keys: List[MaabeKey] = []
        for i in range(len(keysDataList) // 3):
            keys.append(MaabeKey(keysDataList[3*i:3*i+3]))
        return keys

    def GenFameAttribKeys(self,
                           secKey: FameSecKey,
                           attribs: List[str]
                           ) -> Union[FameKey, None]:
        """Wrapper function for libahe's Ahe_maabe_GenerateAttribKeys.

        :param auth:                    the authority generating the keys
        :type auth:                     :class:`MaabeAuth`
        :param gid:                     a string global id for the user
        :type gid:                      str
        :param attribs:                 a list of attributes the user wants
                                        keys for
        :type attribs:                  list[str]
        :return:                        a list of MaabeKey objects
                                        encapsulating single keys
        :rtype:                         list[:class:`MaabeKey`]
        :raises AheEmptyMaabeAuth:      empty MaabeAuth() object passed
        :raises AheEmptyGid:            empty GID string passed
        :raises AheEmptyAttributeList:  empty attribs list passed
        :raises AheEmptyAttribute:      the attribs list contains an empty
                                        attribute
        """
        if not attribs:
            raise(AheEmptyAttributeList)
        for at in attribs:
            if not at:
                raise(AheEmptyAttribute)

        maabeStr: str = self.scheme.toString()
        maabeC: ctypes.c_char_p = Ahe.python_str_to_c_charp(maabeStr)
        secStr: str = secKey.toString()
        secC: ctypes.c_char_p = Ahe.python_str_to_c_charp(secStr)
        attribsC: CHARPP = Ahe.python_strlist_to_c_charpp(attribs)
        keysC: StringList = self.fame_gen_keys(maabeC,
                                               attribsC,
                                               len(attribs),
                                               secC)
        keysDataList: List[str] = Ahe.c_charpp_to_python_strlist(keysC.data,
                                                                 keysC.length)

        return FameKey(keysDataList)

    def Decrypt(self,
                ct: Union[MaabeCipher, FameCipher],
                ks: Union[List[MaabeKey], FameKey],
                pk: Union[FamePubKey, None] = None
                ) -> Union[str, None]:
        """Wrapper function for libahe's Ahe_maabe_Decrypt.

        :param maabe:                   the public parameters
        :type maabe:                    :class:`Maabe`
        :param ct:                      the ciphertext
        :type ct:                       :class:`MaabeCipher`
        :param ks:                      a list of decryption keys
        :type ks:                       list[:class:`MaabeKey`]
        :return:                        the plaintext (or None)
        :rtype:                         str
        :raises AheEmptyScheme:          empty Maabe() object passed
        :raises AheEmptyCipher:    empty MaabeCipher() object passed
        :raises AheEmptyKeyList:   empty ks list passed
        :raises AheEmptyKey:       the ks list contains an empty
                                        MaabeKey() object
        """
        if self.scheme_type == "maabe":
            res = self.DecryptMaabe(self.scheme, ct, ks)
            return res

        if self.scheme_type == "fame":
            res = self.DecryptFame(self.scheme, ct, ks, pk)
            return res

    def DecryptMaabe(self,
                maabe: Maabe,
                ct: MaabeCipher,
                ks: List[MaabeKey],
                ) -> Union[str, None]:
        """Wrapper function for libahe's Ahe_maabe_Decrypt.

        :param maabe:                   the public parameters
        :type maabe:                    :class:`Maabe`
        :param ct:                      the ciphertext
        :type ct:                       :class:`MaabeCipher`
        :param ks:                      a list of decryption keys
        :type ks:                       list[:class:`MaabeKey`]
        :return:                        the plaintext (or None)
        :rtype:                         str
        :raises AheEmptyScheme:          empty Maabe() object passed
        :raises AheEmptyCipher:    empty MaabeCipher() object passed
        :raises AheEmptyKeyList:   empty ks list passed
        :raises AheEmptyKey:       the ks list contains an empty
                                        MaabeKey() object
        """
        if maabe.isEmpty():
            raise(AheEmptyScheme)
        if ct.isEmpty():
            raise(AheEmptyCipher)
        if not ks:
            raise(AheEmptyKeyList)
        for k in ks:
            if k.isEmpty():
                raise(AheEmptyKey)
        maabeStrList: List[str] = maabe.toStringList()
        maabeC: CHARPP = Ahe.python_strlist_to_c_charpp(maabeStrList)
        ctStrList: List[str] = ct.toStringList()
        ctC: CHARPP = Ahe.python_strlist_to_c_charpp(ctStrList)
        keysStrList: List[str] = []
        for k in ks:
            keysStrList += k.toStringList()
        keysC: CHARPP = Ahe.python_strlist_to_c_charpp(keysStrList)
        ptC: bytes = self.maabe_decrypt(maabeC,
                                        ctC,
                                        len(ctStrList),
                                        keysC,
                                        len(keysStrList))
        if ptC is None:
            return None
        return ptC.decode('utf-8',
                          'strict')

    def DecryptFame(self,
                     maabe: Fame,
                     ct: FameCipher,
                     ks: FameKey,
                     pk: FamePubKey,
                     ) -> Union[str, None]:
        """Wrapper function for libahe's Ahe_maabe_Decrypt.

        :param maabe:                   the public parameters
        :type maabe:                    :class:`Maabe`
        :param ct:                      the ciphertext
        :type ct:                       :class:`MaabeCipher`
        :param ks:                      a list of decryption keys
        :type ks:                       list[:class:`MaabeKey`]
        :return:                        the plaintext (or None)
        :rtype:                         str
        :raises AheEmptyScheme:          empty Maabe() object passed
        :raises AheEmptyCipher:    empty MaabeCipher() object passed
        :raises AheEmptyKeyList:   empty ks list passed
        :raises AheEmptyKey:       the ks list contains an empty
                                        MaabeKey() object
        """
        if maabe.isEmpty():
            raise(AheEmptyScheme)
        if ct.isEmpty():
            raise(AheEmptyCipher)
        if not ks:
            raise(AheEmptyKeyList)
        if ks.isEmpty():
            raise(AheEmptyKey)
        maabeStr: str = maabe.toString()
        maabeC: ctypes.c_char_p = Ahe.python_str_to_c_charp(maabeStr)
        ctStrList: List[str] = ct.toStringList()
        ctC: CHARPP = Ahe.python_strlist_to_c_charpp(ctStrList)
        keysStrList: List[str] = ks.toStringList()
        keysC: CHARPP = Ahe.python_strlist_to_c_charpp(keysStrList)
        pksStr: str = pk.toString()
        pksC: ctypes.c_char_p = Ahe.python_str_to_c_charp(pksStr)
        ptC: bytes = self.fame_decrypt(maabeC,
                                       ctC,
                                       len(ctStrList),
                                       keysC,
                                       len(keysStrList),
                                       pksC)
        if ptC is None:
            return None
        return ptC.decode('utf-8',
                          'strict')

    def VerifyAndDecrypt(self,
                cts: str,
                ks: Union[List[MaabeKey], FameKey],
                pubkey: FamePubKey = None,
                uuid: str = None,
                ca: str = None
                ) -> Union[List[str], None]:
        """Wrapper function for libahe's Ahe_maabe_Decrypt.

        :param maabe:                   the public parameters
        :type maabe:                    :class:`Maabe`
        :param ct:                      the ciphertext
        :type ct:                       :class:`MaabeCipher`
        :param ks:                      a list of decryption keys
        :type ks:                       list[:class:`MaabeKey`]
        :return:                        the plaintext (or None)
        :rtype:                         str
        :raises AheEmptyScheme:          empty Maabe() object passed
        :raises AheEmptyCipher:    empty MaabeCipher() object passed
        :raises AheEmptyKeyList:   empty ks list passed
        :raises AheEmptyKey:       the ks list contains an empty
                                        MaabeKey() object
        """

        ok = self.Verify(cts, uuid, ca)
        if not ok:
            raise AheVerificationError("verification failed")


        ciphers = self.CiphersFromJSON(cts)
        plaintexts = []
        for ct in ciphers:
            msg = self.Decrypt(ct, ks, pubkey)
            plaintexts.append(msg)

        return plaintexts

    def PubKeyToJSON(self,
                     pk: MaabePubKey
                     ) -> Union[str, None]:
        """Wrapper function for libahe's Ahe_maabe_PubKeyToJSON.

        :param pk:                  the public key to be marshaled
        :type pk:                   :class:`MaabePubKey`
        :return:                    the json string (or None)
        :rtype:                     str
        :raises AheEmptyPublicKey:  if en empty key is passed
        """
        if pk.isEmpty():
            raise(AheEmptyPublicKey)
        pkStr: List[str] = pk.toStringList()
        pkC: CHARPP = Ahe.python_strlist_to_c_charpp(pkStr)
        pkJSON: bytes = self.maabe_pk_to_json(pkC,
                                              len(pkC))
        if pkJSON is None:
            return None
        return pkJSON.decode('utf-8',
                             'strict')

    def PubKeyFromJSON(self,
                       data: str
                       ) -> Union[MaabePubKey, None]:
        """Wrapper function for libahe's Ahe_maabe_PubKeyFromJSON.

        :param data:    json data as string
        :type data:     str
        :return:        new public key from the json
        :rtype:         :class:`MaabePubKey`
        """
        jsonC: ctypes.c_char_p = ctypes.c_char_p(data.encode('utf-8',
                                                             'strict'))
        pksC: StringList = self.maabe_pk_from_json(jsonC)
        pksDataList: List[str] = Ahe.c_charpp_to_python_strlist(pksC.data,
                                                                pksC.length)
        if len(pksDataList) % 3 != 0:
            return None
        pks: MaabePubKey = MaabePubKey(pksDataList)
        if pks.isEmpty():
            return None
        return pks

    def AttributeKeysToJSON(self,
                            ks: List[MaabeKey]
                            ) -> Union[str, None]:
        """Wrapper function for libahe's Ahe_maabe_AttribKeysToJSON.

        :param ks:                      the list of attribute keys to be
                                        marshaled
        :type ks:                       List[:class:`MaabeKey`]
        :return:                        the json string (or None)
        :rtype:                         str
        :raises AheEmptyKeyList:   if en empty key list is passed
        :raises AheEmptyKey:       if the key list passed contains an
                                        empty element
        """
        if len(ks) == 0:
            raise(AheEmptyKeyList)
        ksStrList: List[str] = []
        for k in ks:
            if k.isEmpty():
                raise(AheEmptyKey)
            ksStrList += k.toStringList()
        ksC: CHARPP = Ahe.python_strlist_to_c_charpp(ksStrList)
        ksJSON: bytes = self.maabe_ks_to_json(ksC,
                                              len(ksC))
        if ksJSON is None:
            return None
        return ksJSON.decode('utf-8',
                             'strict')

    def AttributeKeysFromJSON(self,
                              data: str
                              ) -> Union[List[MaabeKey], None]:
        """Wrapper function for libahe's Ahe_maabe_AttribKeysFromJSON.

        :param data:    json data as string
        :type data:     str
        :return:        new list of attribute keys from the json
        :rtype:         List[:class:`MaabeKey`]
        """
        jsonC: ctypes.c_char_p = ctypes.c_char_p(data.encode('utf-8',
                                                             'strict'))
        ksC: StringList = self.maabe_ks_from_json(jsonC)
        ksDataList: List[str] = Ahe.c_charpp_to_python_strlist(ksC.data,
                                                               ksC.length)
        if len(ksDataList) % 3 != 0:
            return None
        ks: List[MaabeKey] = []
        for i in range(len(ksDataList) // 3):
            ks.append(MaabeKey(ksDataList[3*i:3*i+3]))
        return ks

    def CiphersToJSON(self, cts: Union[List[MaabeCipher], List[FameCipher]], desc: List[str] = None) -> Union[str, None]:
        """Wrapper function for libahe's Ahe_maabe_CipherToJSON.

        :param ct:                      the cipher to be marshaled
        :type ct:                       :class:`MaabeCipher`
        :return:                        the json string (or None)
        :rtype:                         str
        :raises AheEmptyCipher:    if an empty cipher is passed
        """
        resDict = {}
        for i in range(len(cts)):
            ct = cts[i]
#             if ct.isEmpty():
#                 raise(AheEmptyCipher)
#             ctStr: List[str] = ct.toStringList()
#             ctC: ctypes.POINTER(ctypes.c_char_p) = Ahe.python_strlist_to_c_charpp(ctStr)
#             ctJSON: bytes = self.maabe_ct_to_json(ctC, len(ctC))
# #             if ctJSON is None:
# #                 return None
#             val = None
            if self.scheme_type == "maabe":
                # val = json.loads(ctJSON)["cipher"]
                val = ct.toStringList()
                val = ",".join(val)
            elif self.scheme_type == "fame":
                val = ct.toStringList()
                val = ",".join(val)

            if desc != None:
                resDict[desc[i]] = val
            else:
                resDict["cipher" + str(i)] = val

        ctsJSON = json.dumps(resDict, separators=(',', ':'))
#         return ctsJSON.decode('utf-8', 'strict')
        return ctsJSON

    def CiphersFromJSON(self, data: str) -> Union[List[MaabeCipher], List[FameCipher], None]:
        """Wrapper function for libahe's Ahe_maabe_CipherFromJSON.

        :param data:    json data as string
        :type data:     str
        :return:        new cipher from the json
        :rtype:         :class:`MaabeCipher`
        """
        cts: Union[List[MaabeCipher], List[FameCipher]] = []
        ctsDict = json.loads(data)
        for key in ctsDict.keys():
            if key in ["signature", "proof"]:
                continue

            if self.scheme_type == "maabe":
                cipherList = ctsDict[key].split(",")
                ct: MaabeCipher = MaabeCipher(cipherList)
                cts.append(ct)
                # tmp = {"cipher": ctsDict[key]}
                # tmpString = json.dumps(tmp, separators=(',', ':'))
                # jsonC: ctypes.c_char_p = ctypes.c_char_p(tmpString.encode('utf-8', 'strict'))
                # ctC: StringList = self.maabe_ct_from_json(jsonC)
                # ctDataList: List[str] = Ahe.c_charpp_to_python_strlist(ctC.data, ctC.length)
                # if (len(ctDataList) - 6) % 4 != 0:
                #     return None
                # ct: MaabeCipher = MaabeCipher(ctDataList)
                # if ct.isEmpty():
                #     return None
                # cts.append(ct)
            elif self.scheme_type == "fame":
                cipherList = ctsDict[key].split(",")
                ct: FameCipher = FameCipher(cipherList)
                cts.append(ct)
        return cts

    @staticmethod
    def c_charp_to_python_str(charp: ctypes.c_char_p,
                                   ) -> str:
        """Converts from char * (in C) to str (in Python).
        """
        return charp.decode('utf-8', 'strict')


    @staticmethod
    def c_charpp_to_python_strlist(charpp: CHARPP,
                                   length: int
                                   ) -> List[str]:
        """Converts from char ** (in C) to list[str] (in Python).

        :param charpp:                  a pointer to the first element of the
                                        data list
        :type charpp:                   :class:`CHARPP`
        :param length:                  length of the data list
        :type length:                   int
        :return:                        the list of strings represented by the
                                        data list
        :rtype:                         list[str]
        :raises AheTypeConversionError: something went wrong when converting
                                        char ** to list[str], contains a
                                        message
        """
        if charpp is None:
            raise(AheTypeConversionError("Pointer cannot be NULL"))
        if length <= 0:
            raise(AheTypeConversionError("Array length cannot be <= 0"))
        byteList = [charpp[i] for i in range(length)]
        strList = []
        for i in range(len(byteList)):
            strList.append(byteList[i].decode('utf-8', 'strict'))
        return strList

    @staticmethod
    def python_str_to_c_charp(string: str
                                   ) -> ctypes.c_char_p:
        """Converts from str (in Python) to char * (in C).
        """
        if not string:
            error_msg = "Cannot convert an empty string"
            raise(AheTypeConversionError(error_msg))

        return string.encode('utf-8', 'strict')

    @staticmethod
    def python_strlist_to_c_charpp(strList: List[str]
                                   ) -> CHARPP:
        """Converts from list[str] (in Python) to char ** (in C).

        :param strList:                 a list of strings we want to pass to C
        :type strList:                  list[str]
        :return:                        a pointer to the data list in memory
        :rtype:                         :class:`CHARPP`
        :raises AheTypeConversionError: something went wrong when converting
                                        list[str] to char ** , contains a
                                        message
        """
        if not strList:
            error_msg = "Cannot convert an empty list"
            raise(AheTypeConversionError(error_msg))
        for s in strList:
            if not s:
                error_msg = "Should not convert a list with empty elements"
                raise(AheTypeConversionError(error_msg))
        byteList = []
        for i in range(len(strList)):
            byteList.append(strList[i].encode('utf-8',
                                              'strict'))
        charpp: CHARPP = (ctypes.c_char_p * len(byteList))()
        charpp[:] = byteList
        return charpp

    def GenerateSigningKeys(self, wallet: str = "signing_private_key.txt") -> Union[str, None]:
        """Generate a private signing key in the eSIM and output the corresponding public key.

        :return:                        the public signing key needed for the verification (or None)
        :rtype:                         str
        """
        keys: MasterKeys = self.sig_generate_keys()
        self.ver_key = Ahe.c_charp_to_python_str(keys.pk)
        signing_key = Ahe.c_charp_to_python_str(keys.sk)
        w = open(wallet, "w")
        w.write(signing_key + "\n")
        w.close()

        return self.ver_key


    def Sign(self, cts: Union[List[MaabeCipher], List[FameCipher]], wallet: str = "signing_private_key.txt", proof: str = None) -> Union[str, None]:
        """A function to sign a list of ciphertext in the eSIM and produce a signed JSON.

        :param cts:                     A list of cihertexts to be signed.
        :type ct:                       List[:class:`MaabeCipher`]
        :return:                        the signed json string (or None)
        :rtype:                         str
        :raises AheEmptyCipher:    if an empty list of ciphertext is passed
        """
        if proof != None :
            proof_char_p = Ahe.python_str_to_c_charp(proof)
        else:
            proof_char_p = None

        o = open(wallet)
        sigkey_string = o.readline().strip()
        o.close()
        sigkey = Ahe.python_str_to_c_charp(sigkey_string)
        cts_strings = [",".join(ct.toStringList()) for ct in cts]
        cts_charpp: CHARPP = Ahe.python_strlist_to_c_charpp(cts_strings)
        cts_signed = self.sig_sign_ciphers(sigkey, cts_charpp, len(cts), proof_char_p)
        cts_signed_string = Ahe.c_charp_to_python_str(cts_signed)

        return cts_signed_string

    def Verify(self, cts: str, uuid: str = None, ca: str = None) -> bool:
        """Verify that the ciphertexts are properly signed.

        :param cts:                     the signed ciphertext
        :type ct:                       str
        :param uuid:                    uuid of the source of the signature
        :type uuid:                     str
        :param ca:                      the certificate of the CA that signed the public key of the signature
        :type ca:                       str
        :return:                        True if the verification is confirmed, else False
        :rtype:                         bool
        """
        if uuid != None :
            uuid_char_p = Ahe.python_str_to_c_charp(uuid)
        else:
            uuid_char_p = None
        if ca != None :
            ca_char_p = Ahe.python_str_to_c_charp(ca)
        else:
            ca_char_p = None
        cts_char_p = Ahe.python_str_to_c_charp(cts)

        check = self.sig_verify_sig(cts_char_p, uuid_char_p, ca_char_p)

        if check == 1:
            return True
        else:
            return False


    def JoinFameDecAttribKeys(self,
                          secKeys: str,
                          randKeys: List[str]
                          ) -> Union[FameKey, None]:

        secKeysC: ctypes.c_char_p = Ahe.python_str_to_c_charp(secKeys)
        randKeysC: CHARPP = Ahe.python_strlist_to_c_charpp(randKeys)

        keysC: StringList = self.fame_decrypt_keys(secKeysC, randKeysC, len(randKeys))

        keyC: StringList = self.fame_join_dec_keys(keysC.data, keysC.length)

        keyDataList: List[str] = Ahe.c_charpp_to_python_strlist(keyC.data,
                                                                 keyC.length)

        return FameKey(keyDataList)

if __name__ == '__main__':
    print("Sir, this is a library.")
