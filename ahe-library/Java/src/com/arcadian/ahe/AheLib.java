package com.arcadian.ahe;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import com.arcadian.ahe.type.FameMasterKey;

/**
 * This class represents the <code>libahe.so</code> shared object.
 *
 * @author  Benjamin Benčina Tilen Marc
 * @version 0.0.1
 */
public interface AheLib extends Library {
    /**
     * Interface for the <code>Ahe_maabe_NewMAABE</code> function in <code>libahe.so</code>.
     *
     * @return  pointer to the new Maabe data
     */
    PointerByReference Ahe_maabe_NewMAABE();

    /**
     * Interface for the <code>Ahe_maabe_NewMAABEAuth</code> function in <code>libahe.so</code>.
     *
     * @param   maabeRawC   the string array representation of the Maabe object
     * @param   id          the string id of the new authority
     * @param   attribs     a string list of the attributes managed by this authority
     * @param   attribsLen  the length of the attribute list (needed in C)
     * @return  a C-style string array of the authority data
     */
    DataArray.ByValue Ahe_maabe_NewMAABEAuth(String[] maabeRawC,
                                             String id,
                                             String[] attribs,
                                             int attribsLen);

    /**
     * Interface for the <code>Ahe_maabe_MaabeAuthPubKeys</code> function in <code>libahe.so</code>.
     * Not really needed in languages like Java since everything can be handled
     * through types as in {@link com.arcadian.ahe.type}.
     *
     * @param   authC       a string list representing the authority
     * @param   authCLen    the length of the string list
     * @return  a C-style string array of public keys
     */
    DataArray.ByValue Ahe_maabe_MaabeAuthPubKeys(String[] authC,
                                                 int authCLen);

    /**
     * Interface for the <code>Ahe_maabe_AddAttribute</code> function in <code>libahe.so</code>.
     * Not really needed in languages like Java since everything can be handled
     * through types as in {@link com.arcadian.ahe.type}.
     *
     * @param   authC       a string list representing the authority
     * @param   authCLen    the length of the string list
     * @param   attrib      the string name of the attribute to add
     * @return  a C-style string array of the authority data
     */
    DataArray.ByValue Ahe_maabe_AddAttribute(String[] authC,
                                             int authCLen,
                                             String attrib);

    /**
     * Interface for the <code>Ahe_maabe_Encrypt</code> function in <code>libahe.so</code>.
     *
     * @param   maabeRawC       the string array representation of the Maabe object
     * @param   msg             the string message to encrypt
     * @param   booleanFormula  the decryption policy
     * @param   pubkeys         the string array representation of a list of public keys
     * @param   pubkeysLen      the length of the public key list
     * @return  a C-style array of the ciphertext data
     */
    DataArray.ByValue Ahe_maabe_Encrypt(String[] maabeRawC,
                                        String msg,
                                        String booleanFormula,
                                        String[] pubkeys,
                                        int pubkeysLen);

    /**
     * Interface for the <code>Ahe_maabe_GenerateAttribKeys</code> function in
     * <code>libahe.so</code>.
     *
     * @param   authC       the string array representation of the MaabeAuth object
     * @param   authCLen    the length of the authority array
     * @param   gid         the string global identifier of the user requesting the keys
     * @param   attribs     the string list of attributes requested
     * @param   attribsLen  the length of the attribute array
     * @return  a C-style array of keys
     */
    DataArray.ByValue Ahe_maabe_GenerateAttribKeys(String[] authC,
                                                   int authCLen,
                                                   String gid,
                                                   String[] attribs,
                                                   int attribsLen);

    /**
     * Interface for the <code>Ahe_maabe_Decrypt</code> function in <code>libahe.so</code>.
     *
     * @param   maabeRawC   the string array representation of the Maabe object
     * @param   ctRawC      the string array representation of the ciphertext data
     * @param   ctRawCLen   the length of the ciphertext array
     * @param   ksRawC      the string array representation of a list of decryption keys
     * @param   ksRawCLen   the length of the keys array
     * @return  a C-stype pointer to the plaintext (or <code>NULL</code>)
     */
    Pointer Ahe_maabe_Decrypt(String[] maabeRawC,
                              String[] ctRawC,
                              int ctRawCLen,
                              String[] ksRawC,
                              int ksRawCLen);

    /**
     * Interface for the <code>Ahe_maabe_PubKeyToJSON</code> function in <code>libahe.so</code>.
     *
     * @param   pkC     the string array representation of the MaabePubKey object
     * @param   pkCLen  the length of the pubkey array
     * @return  a string JSON of the public keys
     */
    Pointer Ahe_maabe_PubKeyToJSON(String[] pkC,
                                   int pkCLen);

    /**
     * Interface for the <code>Ahe_maabe_PubKeyFromJSON</code> function in <code>libahe.so</code>.
     *
     * @param   data    JSON data of the pubkey
     * @return  a C-style array of the public keys
     */
    DataArray.ByValue Ahe_maabe_PubKeyFromJSON(String data);

    /**
     * Interface for the <code>Ahe_maabe_AttribKeysToJSON</code> function in <code>libahe.so</code>.
     *
     * @param   ks      the string array representation of the MaabePubKey object
     * @param   ksLen   the length of the pubkey array
     * @return  a string JSON of the attribute keys
     */
    Pointer Ahe_maabe_AttribKeysToJSON(String[] ks,
                                       int ksLen);

    /**
     * Interface for the <code>Ahe_maabe_AttribKeysFromJSON</code> function in
     * <code>libahe.so</code>.
     *
     * @param   data    JSON data of the attribute keys
     * @return  a C-style array of the attribute keys
     */
    DataArray.ByValue Ahe_maabe_AttribKeysFromJSON(String data);

    /**
     * Interface for the <code>Ahe_maabe_CipherToJSON</code> function in <code>libahe.so</code>.
     *
     * @param   ct      the string array representation of the MaabePubKey object
     * @param   ctLen   the length of the pubkey array
     * @return  a string JSON of the ciphertext
     */
    Pointer Ahe_maabe_CipherToJSON(String[] ct,
                                   int ctLen);

    DataArray.ByValue Ahe_maabe_CipherFromJSON(String data);

    Pointer Ahe_fame_NewFAME();

    TwoValue.ByValue Ahe_fame_GenerateMasterKeys(String fameRawC);

    DataArray.ByValue Ahe_fame_Encrypt(String fameRawC,
                                        String msg,
                                        String booleanFormula,
                                        String pubkey);

    DataArray.ByValue Ahe_fame_GenerateAttribKeys(String fameRawC,
                                                  String[] attribs,
                                                  int attribsLen,
                                                  String sk);

    Pointer Ahe_fame_Decrypt(String fameRawC,
                              String[] ctRawC,
                              int ctRawCLen,
                              String[] ksRawC,
                              int ksRawCLen,
                              String pkRaw);

    DataArray.ByValue Ahe_fame_decrytAttribKeys(String sec_keys, String[] rand_keys, int rand_keys_len);

    DataArray.ByValue Ahe_fame_joinDecAttribKeys(String[] keys, int keys_len);
    TwoValue.ByValue Ahe_GenerateSigKeys();

    Pointer Ahe_SignCiphers(String vk,
                            String[] cts,
                            int vkLen,
                            String proof);

    int Ahe_VerifySig(String cts,
                      String uuid,
                      String ca);
}
