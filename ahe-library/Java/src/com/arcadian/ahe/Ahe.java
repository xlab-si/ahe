package com.arcadian.ahe;

import com.arcadian.ahe.exception.AheEmptyAttribute;
import com.arcadian.ahe.exception.AheEmptyAttributeList;
import com.arcadian.ahe.exception.AheEmptyDecryptionPolicy;
import com.arcadian.ahe.exception.AheEmptyGid;
import com.arcadian.ahe.exception.AheEmptyID;
import com.arcadian.ahe.exception.AheEmptyScheme;
import com.arcadian.ahe.exception.AheEmptyMaabeAuth;
import com.arcadian.ahe.exception.AheEmptyCipher;
import com.arcadian.ahe.exception.AheEmptyKey;
import com.arcadian.ahe.exception.AheEmptyKeyList;
import com.arcadian.ahe.exception.AheEmptyMessage;
import com.arcadian.ahe.exception.AheEmptyPublicKey;
import com.arcadian.ahe.exception.AheEmptyPublicKeyList;
import com.arcadian.ahe.exception.AheJSONMarshalError;
import com.arcadian.ahe.exception.AheJSONUnmarshalError;
import com.arcadian.ahe.exception.AheOperationOnEmptyObject;
import com.arcadian.ahe.type.Maabe;
import com.arcadian.ahe.type.MaabeAuth;
import com.arcadian.ahe.type.MaabeCipher;
import com.arcadian.ahe.type.MaabeKey;
import com.arcadian.ahe.type.MaabePubKey;
import com.arcadian.ahe.type.MaabeSecKey;
import com.arcadian.ahe.type.Fame;
import com.arcadian.ahe.type.FameSecKey;
import com.arcadian.ahe.type.FamePubKey;
import com.arcadian.ahe.type.FameMasterKey;
import com.arcadian.ahe.type.FameCipher;
import com.arcadian.ahe.type.FameKey;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.util.Arrays;

/**
 * This class is the entry point to the Arcadian-IoT Hardened Encryption library.
 * It is responsible for loading the shared object (<code>libahe.so</code> on
 * Unix-like operating system and <code>ahe.dll</code> on MS Windows) and for
 * interfacing all native functions into using Java objects as arguments and
 * return values. It is also responsible for throwing any kind of errors as
 * defined in {@link com.arcadian.ahe.exception}.
 *
 * @author  Benjamin Benčina, Tilen Marc
 */
public class Ahe {
    /**
     * The library object to be loaded into memory.
     */
    protected static AheLib ahe;
    public Maabe maabe_scheme;
    public Fame fame_scheme;
    public String scheme;

    /**
     * This constructor is responsible for loading the library.
     * If the library is not found in the Java path, the current behaviour is to halt the program.
     */
    public Ahe() {
        try {
            ahe = (AheLib) Native.load("ahe",
                                       AheLib.class);
            
        } catch (Exception e) {
            System.err.println("Error loading libahe.so: " + e);
            System.exit(1);
        }
    }

    public int SetScheme(String scheme) {
        this.scheme = scheme;
        if (scheme == "maabe") {
            this.maabe_scheme = NewMaabe();
            return 0;
        }

        if (scheme == "fame") {
            this.fame_scheme = NewFame();
            return 0;
        }

        return 1;
    }
    
    
    /**
     * Interface for the <code>Ahe_maabe_NewMAABE</code> function in <code>libahe.so</code>.
     *
     * @return  a new {@link com.arcadian.ahe.type.Maabe} object
     */
    public Maabe NewMaabe() {
        String[] maabeStrList = ahe.Ahe_maabe_NewMAABE().getPointer().getStringArray(0, 4);
        return new Maabe(maabeStrList);
    }

    public Fame NewFame() {
        Pointer famePointer = ahe.Ahe_fame_NewFAME();
        if (famePointer == null) {
            return null;
        }
        String ptStr = famePointer.getString(0);

        return new Fame(ptStr);
    }

    /**
     * Interface for the <code>Ahe_maabe_NewMAABEAuth</code> function in <code>libahe.so</code>.
     *
     * @param   id      the string id of the new authority
     * @param   attribs a string list of the attributes managed by this authority
     * @return  a new {@link com.arcadian.ahe.type.MaabeAuth} object
     * @throws  AheEmptyScheme           if an empty {@link com.arcadian.ahe.type.Maabe} object is
     *                                  passed
     * @throws  AheEmptyID              if an empty string ID is passed
     * @throws  AheEmptyAttributeList   if the list of attributes passed is empty
     * @throws  AheEmptyAttribute       if the list of attributes passed contains an empty element
     */
    public MaabeAuth NewMaabeAuth(String id,
                                  String[] attribs)
    throws AheEmptyScheme,
           AheEmptyID,
           AheEmptyAttributeList,
           AheEmptyAttribute {
        if (this.maabe_scheme.isEmpty()) {
            throw new AheEmptyScheme("in NewMaabeAuth");
        }
        if (id.equals("")) {
            throw new AheEmptyID("in NewMaabeAuth");
        }
        if (attribs.length == 0) {
            throw new AheEmptyAttributeList("in NewMaabeAuth");
        }
        for (String at : attribs) {
            if (at.equals("")) {
                throw new AheEmptyAttribute("in NewMaabeAuth");
            }
        }
        String[] maabeStrList;
        try {
            maabeStrList = this.maabe_scheme.toStringList();
        } catch (AheOperationOnEmptyObject err) {
            throw new AheEmptyScheme("in NewMaabeAuth:maabe.toStringList");
        }
        DataArray auth = ahe.Ahe_maabe_NewMAABEAuth(maabeStrList,
                                                    id,
                                                    attribs,
                                                    attribs.length);
        String[] authStrList = auth.data.getPointer().getStringArray(0, auth.length);
        return new MaabeAuth(authStrList);
    }

    public FameMasterKey NewFameGenerateMasterKeys()
    throws AheEmptyScheme {
        if (this.fame_scheme.isEmpty()) {
            throw new AheEmptyScheme("in NewFameGenarateMasterKeys");
        }

        String fameStr = this.fame_scheme.toString();

        TwoValue masterKey = ahe.Ahe_fame_GenerateMasterKeys(fameStr);

        FameSecKey secKey = new FameSecKey(masterKey.r1.getString(0));
        FamePubKey pubKey = new FamePubKey(masterKey.r0.getString(0));

        FameMasterKey key = new FameMasterKey(pubKey, secKey);

        return key;
    }

    /**
     * Interface for the <code>Ahe_maabe_Encrypt</code> function in <code>libahe.so</code>.
     *
     * @param   msg     the string message to be encrypted
     * @param   bf      the decryption policy in the form of a boolean formula
     * @param   pks     a list of {@link com.arcadian.ahe.type.MaabePubKey} objects consisting of
     *                  all public keys needed for encryption
     * @return  a new {@link com.arcadian.ahe.type.MaabeCipher} object
     * @throws  AheEmptyScheme               if an empty {@link com.arcadian.ahe.type.Maabe} object
     *                                      is passed
     * @throws  AheEmptyMessage             if an empty msg string is passed
     * @throws  AheEmptyDecryptionPolicy    if an empty bf string is passed
     * @throws  AheEmptyPublicKeyList       if the list of public keys passed is empty
     * @throws  AheEmptyPublicKey           if the list of public keys passed contains an empty
     *                                      element
     */
    public MaabeCipher Encrypt(String msg,
                               String bf,
                               MaabePubKey[] pks)
    throws AheEmptyScheme,
           AheEmptyMessage,
           AheEmptyDecryptionPolicy,
           AheEmptyPublicKeyList,
           AheEmptyPublicKey {
        if (this.maabe_scheme.isEmpty()) {
            throw new AheEmptyScheme("in Encrypt");
        }
        if (msg.equals("")) {
            throw new AheEmptyMessage("in Encrypt");
        }
        if (bf.equals("")) {
            throw new AheEmptyDecryptionPolicy("in Encrypt");
        }
        if (pks.length == 0) {
            throw new AheEmptyPublicKeyList("in Encrypt");
        }
        for (MaabePubKey pk : pks) {
            if (pk.isEmpty()) {
                throw new AheEmptyPublicKey("in Encrypt");
            }
        }
        String[] maabeStrList;
        try {
            maabeStrList = this.maabe_scheme.toStringList();
        } catch (AheOperationOnEmptyObject err) {
            throw new AheEmptyScheme("in Encrypt:maabe.toStringList");
        }
        String[] pksStrList = new String[]{};
        for (MaabePubKey pk : pks) {
            String[] pkList;
            try {
                pkList = pk.toStringList();
            } catch (AheOperationOnEmptyObject err) {
                throw new AheEmptyPublicKey("in Encrypt:pk.toStringList");
            }
            pksStrList = concatLists(pksStrList,
                                     pkList);
        }
        DataArray enc = ahe.Ahe_maabe_Encrypt(maabeStrList,
                                              msg,
                                              bf,
                                              pksStrList,
                                              pksStrList.length);
        String[] encStrList = enc.data.getPointer().getStringArray(0, enc.length);
        return new MaabeCipher(encStrList);
    }

    /**
     * Interface for the <code>Ahe_fame_Encrypt</code> function in <code>libahe.so</code>.
     *
     * @param   msg     the string message to be encrypted
     * @param   bf      the decryption policy in the form of a boolean formula
     * @param   pk      a public key needed for encryption
     * @return  a new {@link com.arcadian.ahe.type.FameCipher} object
     * @throws  AheEmptyScheme              if an empty {@link com.arcadian.ahe.type.Fame} object
     *                                      is passed
     * @throws  AheEmptyMessage             if an empty msg string is passed
     * @throws  AheEmptyDecryptionPolicy    if an empty bf string is passed
     * @throws  AheEmptyPublicKey           if the public key passed is empty
     */
    public FameCipher Encrypt(String msg,
                               String bf,
                               FamePubKey pk)
    throws AheEmptyScheme,
           AheEmptyMessage,
           AheEmptyDecryptionPolicy,
           AheEmptyPublicKey {
        if (this.fame_scheme.isEmpty()) {
            throw new AheEmptyScheme("in Encrypt");
        }
        if (msg.equals("")) {
            throw new AheEmptyMessage("in Encrypt");
        }
        if (bf.equals("")) {
            throw new AheEmptyDecryptionPolicy("in Encrypt");
        }
        if (pk.isEmpty() ) {
            throw new AheEmptyPublicKey("in Encrypt");
        }

        String maabeStr;
        maabeStr = this.fame_scheme.toString();

        String pubKeyString = pk.toString();

        DataArray enc = ahe.Ahe_fame_Encrypt(maabeStr,
                                              msg,
                                              bf,
                                              pubKeyString);

        String[] encStrList = enc.data.getPointer().getStringArray(0, enc.length);

        return new FameCipher(encStrList);
    }

    /**
     * Interface for the <code>Ahe_maabe_GenerateAttribKeys</code> function in
     * <code>libahe.so</code>.
     *
     * @param   auth    a {@link com.arcadian.ahe.type.MaabeAuth} object representing the global
     *                  parameters
     * @param   gid     the string global id of the user
     * @param   attribs a string list of the attributes requested
     * @return  a list of new {@link com.arcadian.ahe.type.MaabeKey} objects
     * @throws  AheEmptyMaabeAuth       if an empty {@link com.arcadian.ahe.type.MaabeAuth} object
     *                                  is passed
     * @throws  AheEmptyGid             if an empty string global id is passed
     * @throws  AheEmptyAttributeList   if the list of attributes passed is empty
     * @throws  AheEmptyAttribute       if the list of attributes passed contains an empty element
     */
    public MaabeKey[] GenAttribKeys(MaabeAuth auth,
                                    String gid,
                                    String[] attribs)
    throws AheEmptyMaabeAuth,
           AheEmptyGid,
           AheEmptyAttributeList,
           AheEmptyAttribute {
        if (auth.isEmpty()) {
            throw new AheEmptyMaabeAuth("in GenAttribKeys");
        }
        if (gid.equals("")) {
            throw new AheEmptyGid("in GenAttribKeys");
        }
        if (attribs.length == 0) {
            throw new AheEmptyAttributeList("in GenAttribKeys");
        }
        for (String at : attribs) {
            if (at.equals("")) {
                throw new AheEmptyAttribute("in GenAttribKeys");
            }
        }
        String[] authStrList;
        try {
            authStrList = auth.toStringList();
        } catch (AheOperationOnEmptyObject err) {
            throw new AheEmptyMaabeAuth("in GenAttribKeys:auth.toStringList");
        }
        DataArray keys = ahe.Ahe_maabe_GenerateAttribKeys(authStrList,
                                                          authStrList.length,
                                                          gid,
                                                          attribs,
                                                          attribs.length);
        String[] keysList = keys.data.getPointer().getStringArray(0, keys.length);
        MaabeKey[] ret = new MaabeKey[keysList.length / 3];
        for (int i = 0; i < keysList.length / 3; i++) {
            String[] keyList = Arrays.copyOfRange(keysList,
                                                  3 * i,
                                                  3 * i + 3);
            MaabeKey k = new MaabeKey(keyList);
            ret[i] = k;
        }
        return ret;
    }

    public FameKey GenAttribKeys(FameSecKey sk,
                                 String[] attribs)
    throws AheEmptyAttributeList,
           AheEmptyAttribute {
        if (attribs.length == 0) {
            throw new AheEmptyAttributeList("in GenAttribKeys");
        }
        for (String at : attribs) {
            if (at.equals("")) {
                throw new AheEmptyAttribute("in GenAttribKeys");
            }
        }

        String fameStr = this.fame_scheme.toString();
        String skStr = sk.toString();

        DataArray keys = ahe.Ahe_fame_GenerateAttribKeys(fameStr,
                                                         attribs,
                                                         attribs.length,
                                                         skStr);
        String[] keysList = keys.data.getPointer().getStringArray(0, keys.length);
        FameKey ret = new FameKey(keysList);

        return ret;
    }

    /**
     * Interface for the <code>Ahe_maabe_Decrypt</code> function in <code>libahe.so</code>.
     *
     * @param   ct      a {@link com.arcadian.ahe.type.MaabeCipher} object representing the
     *                  ciphertext
     * @param   ks      a list of {@link com.arcadian.ahe.type.MaabeKey} objects consisting of all
     *                  decryption keys needed
     * @return  a string plaintext on success, or <code>null</code> otherwise
     * @throws  AheEmptyScheme           if an empty {@link com.arcadian.ahe.type.Maabe} object is
     *                                  passed
     * @throws  AheEmptyCipher     if an empty {@link com.arcadian.ahe.type.MaabeCipher}
     *                                  object is passed
     * @throws  AheEmptyKeyList    if the list of decryption keys passed is empty
     * @throws  AheEmptyKey        if the list of decryption keys passed contains an empty
     *                                  element
     */
    public String Decrypt(MaabeCipher ct,
                          MaabeKey[] ks)
    throws AheEmptyScheme,
           AheEmptyCipher,
           AheEmptyKeyList,
           AheEmptyKey {
        if (this.maabe_scheme.isEmpty()) {
            throw new AheEmptyScheme("in Decrypt");
        }
        if (ct.isEmpty()) {
            throw new AheEmptyCipher(" in Decrypt");
        }
        if (ks.length == 0) {
            throw new AheEmptyKeyList("in Decrypt");
        }
        for (MaabeKey k : ks) {
            if (k.isEmpty()) {
                throw new AheEmptyKey("in Decrypt");
            }
        }
        String[] maabeStrList;
        String[] ctStrList;
        try {
            maabeStrList = this.maabe_scheme.toStringList();
        } catch (AheOperationOnEmptyObject err) {
            throw new AheEmptyScheme("in Decrypt:maabe.toStringList");
        }
        try {
            ctStrList = ct.toStringList();
        } catch (AheOperationOnEmptyObject err) {
            throw new AheEmptyCipher("in Decrypt:ct.toStringList");
        }
        String[] keysList = new String[]{};
        for (MaabeKey k : ks) {
            String[] kList;
            try {
                kList = k.toStringList();
            } catch (AheOperationOnEmptyObject err) {
                throw new AheEmptyKey("in Decrypt:k.toStringList");
            }
            keysList = concatLists(keysList,
                                   kList);
        }
        Pointer pt = ahe.Ahe_maabe_Decrypt(maabeStrList,
                                           ctStrList,
                                           ctStrList.length,
                                           keysList,
                                           keysList.length);
        if (pt == null) {
            return null;
        }
        String ptStr = pt.getString(0);
        return ptStr;
    }

    /**
     * Interface for the <code>Ahe_fame_Decrypt</code> function in <code>libahe.so</code>.
     *
     * @param   ct      a {@link com.arcadian.ahe.type.FameCipher} object representing the
     *                  ciphertext
     * @param   ks      a {@link com.arcadian.ahe.type.FameKey} object representing a decryption key
     * @return  a string plaintext on success, or <code>null</code> otherwise
     * @throws  AheEmptyScheme           if object {@link com.arcadian.ahe.type.Fame} object is not set
     * @throws  AheEmptyCipher     if an empty {@link com.arcadian.ahe.type.FameCipher}
     *                                  object is passed
     * @throws  AheEmptyKey        if an empty decryption key is passed
     */
    public String Decrypt(FameCipher ct,
                          FameKey ks,
                          FamePubKey pk)
    throws AheEmptyScheme,
           AheEmptyCipher,
           AheEmptyKey {
        if (this.fame_scheme.isEmpty()) {
            throw new AheEmptyScheme("in Decrypt");
        }
        if (ct.isEmpty()) {
            throw new AheEmptyCipher(" in Decrypt");
        }
        if (ks.isEmpty()) {
            throw new AheEmptyKey("in Decrypt");
        }

        String fameStr = this.fame_scheme.toString();
        String[] ctStrList;
        try {
            ctStrList = ct.toStringList();
        } catch (AheOperationOnEmptyObject err) {
            throw new AheEmptyCipher("in Decrypt:ct.toStringList");
        }
        String[] kList;
        try {
            kList = ks.toStringList();
        } catch (AheOperationOnEmptyObject err) {
            throw new AheEmptyKey("in Decrypt:k.toStringList");
        }

        String pkStr = pk.toString();

        Pointer pt = ahe.Ahe_fame_Decrypt(fameStr,
                                          ctStrList,
                                          ctStrList.length,
                                          kList,
                                          kList.length,
                                          pkStr);
        if (pt == null) {
            return null;
        }
        String ptStr = pt.getString(0);
        return ptStr;
    }

    /**
     * Interface for the <code>Ahe_maabe_PubKeyToJSON</code> function in <code>libahe.so</code>.
     *
     * @param   pk      a {@link com.arcadian.ahe.type.MaabePubKey} object representing the public
     *                  key
     * @return  a string json of the public key
     * @throws  AheEmptyPublicKey       if an empty {@link com.arcadian.ahe.type.MaabePubKey}
     *                                  object is passed
     * @throws  AheJSONMarshalError     if there is a marshaling error
     */
    public String PubKeyToJSON(MaabePubKey pk) 
    throws AheEmptyPublicKey,
           AheJSONMarshalError {
        if (pk.isEmpty()) {
            throw new AheEmptyPublicKey("in PubKeyToJSON");
        }
        String[] pkStrList;
        try {
            pkStrList = pk.toStringList();
        } catch (AheOperationOnEmptyObject err) {
            throw new AheEmptyPublicKey("in PubKeyToJSON");
        }
        Pointer json = ahe.Ahe_maabe_PubKeyToJSON(pkStrList,
                                                  pkStrList.length);
        if (json == null) {
            throw new AheJSONMarshalError("in PubKeyToJSON");
        }
        String jsonStr = json.getString(0);
        return jsonStr;
    }

    /**
     * Interface for the <code>Ahe_maabe_PubKeyFromJSON</code> function in <code>libahe.so</code>.
     *
     * @param   data    a string json representing the pubkey
     * @return  the public key
     * @throws  AheJSONUnmarshalError   if there is an unmarshaling error
     */
    public MaabePubKey PubKeyFromJSON(String data)
    throws AheJSONUnmarshalError {
        if (data.equals("")) {
            throw new AheJSONUnmarshalError("in PubKeyFromJSON - must not be empty");
        }
        DataArray pk = ahe.Ahe_maabe_PubKeyFromJSON(data);
        if (pk.length == 0) {
            throw new AheJSONUnmarshalError("in PubKeyFromJSON");
        }
        String[] pkStrList = pk.data.getPointer().getStringArray(0, pk.length);
        return new MaabePubKey(pkStrList);
    }

    /**
     * Interface for the <code>Ahe_maabe_AttribKeysToJSON</code> function in <code>libahe.so</code>.
     *
     * @param   ks      a list of {@link com.arcadian.ahe.type.MaabeKey} objects representing the
     *                  attribute keys
     * @return  a string json of the attribute keys
     * @throws  AheEmptyKeyList        if an empty {@link com.arcadian.ahe.type.MaabeKey}
     *                                      list is passed
     * @throws  AheEmptyKey            if the list of {@link com.arcadian.ahe.type.MaabeKey}
     *                                      objects contains an empty element
     * @throws  AheJSONMarshalError         if there is a marshaling error
     */
    public String AttribKeysToJSON(MaabeKey[] ks) 
    throws AheEmptyKey,
           AheEmptyKeyList,
           AheJSONMarshalError {
        if (ks.length == 0) {
            throw new AheEmptyKeyList("in AttribKeysToJSON");
        }
        String[] ksStrList = new String[]{};
        for (MaabeKey k : ks) {
            String[] kStrList;
            try {
                kStrList = k.toStringList();
            } catch (AheOperationOnEmptyObject err) {
                throw new AheEmptyKey("in AttribKeysToJSON");
            }
            ksStrList = concatLists(ksStrList,
                                    kStrList);
        }
        Pointer json = ahe.Ahe_maabe_AttribKeysToJSON(ksStrList,
                                                      ksStrList.length);
        if (json == null) {
            throw new AheJSONMarshalError("in AttribKeysToJSON");
        }
        String jsonStr = json.getString(0);
        return jsonStr;
    }

    /**
     * Interface for the <code>Ahe_maabe_AttribKeysFromJSON</code> function in
     * <code>libahe.so</code>.
     *
     * @param   data    a string json representing the attribute keys
     * @return  a list of attribute keys
     * @throws  AheJSONUnmarshalError   if there is an unmarshaling error
     */
    public MaabeKey[] AttribKeysFromJSON(String data)
    throws AheJSONUnmarshalError {
        if (data.equals("")) {
            throw new AheJSONUnmarshalError("in AttribKeysFromJSON - must not be empty");
        }
        DataArray ks = ahe.Ahe_maabe_AttribKeysFromJSON(data);
        if (ks.length == 0) {
            throw new AheJSONUnmarshalError("in AttribKeysFromJSON");
        }
        String[] ksStrList = ks.data.getPointer().getStringArray(0, ks.length);
        MaabeKey[] ret = new MaabeKey[ksStrList.length / 3];
        for (int i = 0; i < ksStrList.length / 3; i++) {
            String[] kStrList = Arrays.copyOfRange(ksStrList,
                                                   3 * i,
                                                   3 * i + 3);
            MaabeKey k = new MaabeKey(kStrList);
            ret[i] = k;
        }
        return ret;
    }

    /**
     * Interface for the <code>Ahe_maabe_CipherToJSON</code> function in <code>libahe.so</code>.
     *
     * @param   ct      a {@link com.arcadian.ahe.type.MaabeCipher} object representing the
     *                  ciphertext
     * @return  a string json of the ciphertext
     * @throws  AheEmptyCipher         if an empty {@link com.arcadian.ahe.type.MaabeCipher}
     *                                      object is passed
     * @throws  AheJSONMarshalError         if there is a marshaling error
     */
    public String CipherToJSON(MaabeCipher ct) 
    throws AheEmptyCipher,
           AheJSONMarshalError {
        if (ct.isEmpty()) {
            throw new AheEmptyCipher("in CipherToJSON");
        }
        String[] ctStrList;
        try {
            ctStrList = ct.toStringList();
        } catch (AheOperationOnEmptyObject err) {
            throw new AheEmptyCipher("in CipherToJSON");
        }
        Pointer json = ahe.Ahe_maabe_CipherToJSON(ctStrList,
                                                  ctStrList.length);
        if (json == null) {
            throw new AheJSONMarshalError("in CipherToJSON");
        }
        String jsonStr = json.getString(0);
        return jsonStr;
    }

    /**
     * Interface for the <code>Ahe_maabe_CipherFromJSON</code> function in <code>libahe.so</code>.
     *
     * @param   data    a string json representing the ciphertext
     * @return  the ciphertext
     * @throws  AheJSONUnmarshalError   if there is an unmarshaling error
     */
    public MaabeCipher CipherFromJSON(String data)
    throws AheJSONUnmarshalError {
        if (data.equals("")) {
            throw new AheJSONUnmarshalError("in CipherFromJSON - must not be empty");
        }
        DataArray ct = ahe.Ahe_maabe_CipherFromJSON(data);
        if (ct.length == 0) {
            throw new AheJSONUnmarshalError("in CipherFromJSON");
        }
        String[] ctStrList = ct.data.getPointer().getStringArray(0, ct.length);
        return new MaabeCipher(ctStrList);
    }

    /**
     * Concatenates two list of strings into a single string list.
     *
     * @param   a   the first list
     * @param   b   the second list
     * @return  a list of elements from first a then b
     */
    public static String[] concatLists(String[] a, String[] b) {
        String[] ret = new String[a.length + b.length];
        int i = 0;
        for (String ent : a) {
            ret[i] = ent;
            i++;
        }
        for (String ent : b) {
            ret[i] = ent;
            i++;
        }
        return ret;
    }

    public FameKey JoinDecAttribKeys(String sec_keys, String[] rand_keys) {
        DataArray keys = ahe.Ahe_fame_decrytAttribKeys(sec_keys, rand_keys, rand_keys.length);
        String[] keysList = keys.data.getPointer().getStringArray(0, keys.length);

        DataArray keyC = ahe.Ahe_fame_joinDecAttribKeys(keysList, keys.length);

        String[] keyList = keyC.data.getPointer().getStringArray(0, keyC.length);

        FameKey ret = new FameKey(keyList);

        return ret;
    }

    /**
     * Interface for the <code>Ahe_GenerateSigKeys</code> function in <code>libahe.so</code>.
     *
     * @return  List of two strings representing public and private signing key.
     */
    public String[] GenerateSigningKeys() {
        TwoValue masterKey = ahe.Ahe_GenerateSigKeys();
        String pk = masterKey.r0.getString(0);
        String sk = masterKey.r1.getString(0);
        String[] ret = new String[2];
        ret[0] = pk;
        ret[1] = sk;

        return ret;
    }

    /**
     * Interface for the <code>Ahe_SignCiphers</code> function in <code>libahe.so</code>.
     *
     * @param   cts   A list of fame ciphers that need to be signed.
     * @param   sk   A private signing key need to sign.
     * @param   proof   A proof that the public signature key corresponds to the uuid of the signer
     * @return  A string that represents a JSON with all the ciphertexts and a signature.
     */
    public String Sign(FameCipher[] cts, String sk, String proof)
    throws AheEmptyCipher {
        String[] ctsStrings = new String[cts.length];
        for (int i = 0; i < cts.length; i++) {
                try {
                    ctsStrings[i] = String.join(",", cts[i].toStringList());
                } catch (AheOperationOnEmptyObject err) {
                    throw new AheEmptyCipher("in Sign:cipher.toStringList");
                }

        }

        Pointer ctsSignedPointer = ahe.Ahe_SignCiphers(sk, ctsStrings, cts.length, proof);
        String ctsSigned = ctsSignedPointer.getString(0);

        return ctsSigned;
    }

    /**
     * Interface for the <code>Ahe_SignCiphers</code> function in <code>libahe.so</code>.
     *
     * @param   cts   A list of fame ciphers that need to be signed.
     * @param   sk   A private signing key need to sign.
     * @return  A string that represents a JSON with all the ciphertexts and a signature.
     */
    public String Sign(FameCipher[] cts, String sk)
    throws AheEmptyCipher {
        return this.Sign(cts, sk, "");
    }

    /**
     * Interface for the <code>Ahe_VerifySig</code> function in <code>libahe.so</code>.
     *
     * @param   cts   A string representing JSON with all the ciphertexts and a signature.
     * @param   uuid  Unique name of the signer.
     * @param   ca  Certificate of the CA that signed the public key corresponding to the signer.
     * @return  A boolean indicating if the signature is correct.
     */
    public boolean Verify(String cts, String uuid, String ca) {
        int check = ahe.Ahe_VerifySig(cts, uuid, ca);
        if (check == 0) {
            return false;
            }
        return true;
    }

    /**
     * Interface for the <code>Ahe_VerifySig</code> function in <code>libahe.so</code>.
     *
     * @param   cts   A string representing JSON with all the ciphertexts and a signature.
     * @param   vk   A public signing key of the signature, it can be null if we trust the public key included in cts.
     * @return  A boolean indicating if the signature is correct.
     */
    public boolean Verify(String cts) {
        return Verify(cts, "", "");
    }
}
