package com.arcadian.ahe.test;

import junit.framework.TestCase;
import static org.junit.Assert.assertThrows;

import com.arcadian.ahe.Ahe;

import com.arcadian.ahe.type.Maabe;
import com.arcadian.ahe.type.MaabeAuth;
import com.arcadian.ahe.type.MaabePubKey;
import com.arcadian.ahe.type.MaabeSecKey;
import com.arcadian.ahe.type.MaabeKey;
import com.arcadian.ahe.type.MaabeCipher;
import com.arcadian.ahe.type.Fame;
import com.arcadian.ahe.type.FameSecKey;
import com.arcadian.ahe.type.FamePubKey;
import com.arcadian.ahe.type.FameMasterKey;
import com.arcadian.ahe.type.FameCipher;
import com.arcadian.ahe.type.FameKey;

import com.arcadian.ahe.exception.AheEmptyMessage;
import com.arcadian.ahe.exception.AheEmptyDecryptionPolicy;
import com.arcadian.ahe.exception.AheEmptyGid;
import com.arcadian.ahe.exception.AheEmptyAttribute;
import com.arcadian.ahe.exception.AheEmptyAttributeList;
import com.arcadian.ahe.exception.AheEmptyPublicKey;
import com.arcadian.ahe.exception.AheEmptyPublicKeyList;
import com.arcadian.ahe.exception.AheEmptyID;
import com.arcadian.ahe.exception.AheEmptyScheme;
import com.arcadian.ahe.exception.AheEmptyMaabeAuth;
import com.arcadian.ahe.exception.AheEmptyCipher;
import com.arcadian.ahe.exception.AheEmptyKey;
import com.arcadian.ahe.exception.AheEmptyKeyList;
import com.arcadian.ahe.exception.AheOperationOnEmptyObject;
import com.arcadian.ahe.exception.AheJSONMarshalError;
import com.arcadian.ahe.exception.AheJSONUnmarshalError;

import java.net.URL;
import java.net.URLConnection;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.io.OutputStream;
import java.io.InputStream;
import java.util.Scanner;
import java.io.File;

import javax.net.ssl.TrustManager;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.HttpsURLConnection;
import java.net.MalformedURLException;
import java.util.Random;

public class TestAhe extends TestCase {

    public static Ahe a = new Ahe();
    String scheme_type = "maabe";
    int check = a.SetScheme(scheme_type);

    public void testMaabeLifecycle() {
        Maabe m = a.NewMaabe();
        try {
            String id1 = "auth1", id2 = "auth2", id3 = "auth3";
            String[] attribs1 = new String[]{"auth1:at1", "auth1:at2"};
            String[] attribs2 = new String[]{"auth2:at1", "auth2:at2"};
            String[] attribs3 = new String[]{"auth3:at1", "auth3:at2"};
            MaabeAuth auth1 = a.NewMaabeAuth(id1, attribs1);
            MaabeAuth auth2 = a.NewMaabeAuth(id2, attribs2);
            MaabeAuth auth3 = a.NewMaabeAuth(id3, attribs3);
            MaabePubKey[] pks = {auth1.Pk, auth2.Pk, auth3.Pk};
            String msg = "Attack at dawn!";
            String bf = "((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)";
            MaabeCipher ct = a.Encrypt(msg, bf, pks);
            String gid = "user1";
            MaabeKey[] keys1 = a.GenAttribKeys(auth1, gid, attribs1);
            MaabeKey[] keys2 = a.GenAttribKeys(auth2, gid, attribs2);
            MaabeKey[] keys3 = a.GenAttribKeys(auth3, gid, attribs3);
            MaabeKey[] ks1 = {keys1[0], keys2[0], keys3[0]};
            MaabeKey[] ks2 = {keys1[1], keys2[1], keys3[1]};
            MaabeKey[] ks3 = {keys1[0], keys2[1]};
            MaabeKey[] ks4 = {keys1[1], keys2[0]};
            MaabeKey[] ks5 = {keys3[0], keys3[1]};
            String pt1 = a.Decrypt(ct, ks1);
            assertEquals(pt1, msg);
            String pt2 = a.Decrypt(ct, ks2);
            assertEquals(pt2, msg);
            String pt3 = a.Decrypt(ct, ks3);
            assertNull(pt3);
            String pt4 = a.Decrypt(ct, ks4);
            assertNull(pt4);
            String pt5 = a.Decrypt(ct, ks5);
            assertEquals(pt5, msg);
        } catch (Exception e) {
            fail("Unexpected exception.");
        }
    }

    public void testNewMaabeLen() {
        Maabe m = a.NewMaabe();
        try {
            assertEquals(m.toStringList().length, 4);
        } catch (Exception e) {
            fail("Unexpected exception.");
        }
    }

    public void testNewMaabeAuthLen() {
        try {
            String[] ats = new String[]{"at1", "at2", "at3", "at4"};
            MaabeAuth auth = a.NewMaabeAuth("id", ats);
            assertEquals(auth.toStringList().length, 5 + 5*ats.length);
        } catch (Exception e) {
            fail("Unexpected exception.");
        }
    }

    public void testNewMaabeAuthEmpty() {
        Maabe m = a.NewMaabe();
        String[] ats = new String[]{"at1", "at2"};
        String[] atsEmpty = new String[]{};
        String[] atsEmptyEnt = new String[]{"at1", ""};
        String ID = "id";
        String IDEmpty = "";
        AheEmptyID e2 = assertThrows(AheEmptyID.class, () -> a.NewMaabeAuth(IDEmpty, ats));
        AheEmptyAttributeList e3 = assertThrows(AheEmptyAttributeList.class, () -> a.NewMaabeAuth(ID, atsEmpty));
        AheEmptyAttribute e4 = assertThrows(AheEmptyAttribute.class, () -> a.NewMaabeAuth(ID, atsEmptyEnt));
    }

    public void testEncryptLen() {
        Maabe m = a.NewMaabe();
        try {
            String[] ats = new String[]{"at1", "at2"};
            MaabeAuth auth = a.NewMaabeAuth("id", ats);
            String msg = "Attack at dawn!";
            String bf = "(at1 OR at2)";
            MaabeCipher ct = a.Encrypt(msg, bf, new MaabePubKey[]{auth.Pk});
            assertEquals(ct.toStringList().length, 6 + 4*ats.length);
        } catch (Exception e) {
            fail("Unexpected exception.");
        }
    }

    public void testEncryptEmpty() {
        Maabe m = a.NewMaabe();
        Maabe mEmpty = new Maabe();
        MaabeAuth authEmpty = new MaabeAuth();
        String msg = "Attack at dawn!";
        String msgEmpty = "";
        String[] ats = new String[]{"at1", "at2"};
        String bf = "(at1 OR at2)";
        String bfEmpty = "";
        MaabePubKey[] pksEmpty = new MaabePubKey[]{};
        MaabePubKey[] pksEmptyEnt = new MaabePubKey[]{new MaabePubKey()};
        try {
            MaabeAuth auth = a.NewMaabeAuth("id", ats);
            MaabePubKey[] pks = new MaabePubKey[]{auth.Pk};
            AheEmptyMessage e2 = assertThrows(AheEmptyMessage.class, () -> a.Encrypt(msgEmpty, bf, pks));
            AheEmptyDecryptionPolicy e3 = assertThrows(AheEmptyDecryptionPolicy.class, () -> a.Encrypt(msg, bfEmpty, pks));
            AheEmptyPublicKeyList e4 = assertThrows(AheEmptyPublicKeyList.class, () -> a.Encrypt(msg, bf, pksEmpty));
            AheEmptyPublicKey e5 = assertThrows(AheEmptyPublicKey.class, () -> a.Encrypt(msg, bf, pksEmptyEnt));
        } catch (Exception e) {
            fail("Unexpected exception.");
        }
    }

    public void testGenAttribKeysLen() {
        Maabe m = a.NewMaabe();
        try {
            String[] ats = new String[]{"at1", "at2"};
            MaabeAuth auth = a.NewMaabeAuth("id", ats);
            String gid = "user";
            MaabeKey[] ks = a.GenAttribKeys(auth, gid, ats);
            assertEquals(ks.length, ats.length);
            for (MaabeKey k : ks) {
                assertEquals(k.toStringList().length, 3);
            }
        } catch (Exception e) {
            fail("Unexpected exception.");
        }
    }

    public void testGenAttribKeysEmpty() {
        Maabe m = a.NewMaabe();
        String[] ats = new String[]{"at1", "at2"};
        String[] atsEmpty = new String[]{};
        String[] atsEmptyEnt = new String[]{"at1", ""};
        String gid = "gid";
        String gidEmpty = "";
        MaabeAuth authEmpty = new MaabeAuth();
        try {
            MaabeAuth auth = a.NewMaabeAuth("id", ats);
            AheEmptyMaabeAuth e1 = assertThrows(AheEmptyMaabeAuth.class, () -> a.GenAttribKeys(authEmpty, gid, ats));
            AheEmptyGid e2 = assertThrows(AheEmptyGid.class, () -> a.GenAttribKeys(auth, gidEmpty, ats));
            AheEmptyAttributeList e3 = assertThrows(AheEmptyAttributeList.class, () -> a.GenAttribKeys(auth, gid, atsEmpty));
            AheEmptyAttribute e4 = assertThrows(AheEmptyAttribute.class, () -> a.GenAttribKeys(auth, gid, atsEmptyEnt));
        } catch (Exception e) {
            fail("Unexpected exception.");
        }
    }

    public void testDecryptEmpty() {
        Maabe m = a.NewMaabe();
        Maabe mEmpty = new Maabe();
        String[] ats = new String[]{"at1", "at2"};
        String gid = "gid";
        String msg = "Attack at dawn!";
        String bf = "(at1 OR at2)";
        MaabeCipher ctEmpty = new MaabeCipher();
        MaabeKey[] ksEmpty = new MaabeKey[]{};
        MaabeKey[] ksEmptyEnt = new MaabeKey[]{new MaabeKey()};
        try {
            MaabeAuth auth = a.NewMaabeAuth("id", ats);
            MaabePubKey[] pks = new MaabePubKey[]{auth.Pk};
            MaabeCipher ct = a.Encrypt(msg, bf, pks);
            MaabeKey[] ks = a.GenAttribKeys(auth, gid, ats);
            AheEmptyCipher e2 = assertThrows(AheEmptyCipher.class, () -> a.Decrypt(ctEmpty, ks));
            AheEmptyKeyList e3 = assertThrows(AheEmptyKeyList.class, () -> a.Decrypt(ct, ksEmpty));
            AheEmptyKey e4 = assertThrows(AheEmptyKey.class, () -> a.Decrypt(ct, ksEmptyEnt));
        } catch (Exception e) {
            fail("Unexpected exception.");
        }
    }

    public void testToJSONEmpty() {
        MaabePubKey pkEmpty = new MaabePubKey();
        MaabeKey[] ksEmpty = new MaabeKey[]{};
        MaabeKey[] ksEmptyEnt = new MaabeKey[]{new MaabeKey()};
        MaabeCipher ctEmpty = new MaabeCipher();
        AheEmptyPublicKey e1 = assertThrows(AheEmptyPublicKey.class, () -> a.PubKeyToJSON(pkEmpty));
        AheEmptyKeyList e2 = assertThrows(AheEmptyKeyList.class, () -> a.AttribKeysToJSON(ksEmpty));
        AheEmptyKey e3 = assertThrows(AheEmptyKey.class, () -> a.AttribKeysToJSON(ksEmptyEnt));
        AheEmptyCipher e4 = assertThrows(AheEmptyCipher.class, () -> a.CipherToJSON(ctEmpty));
    }

    public void testJSONUnmarshal() {
        // this is a valid json but ofc has nothing to do with pubkeys, attrib keys, or ciphers
        String deg = "{\"name\":\"John\", \"age\":30, \"car\":null}";
        AheJSONUnmarshalError e1 = assertThrows(AheJSONUnmarshalError.class, () -> a.PubKeyFromJSON(deg));
        AheJSONUnmarshalError e2 = assertThrows(AheJSONUnmarshalError.class, () -> a.AttribKeysFromJSON(deg));
        AheJSONUnmarshalError e3 = assertThrows(AheJSONUnmarshalError.class, () -> a.CipherFromJSON(deg));
        // invalid jsons with the correct head
        String pkdeg = "{\"pubkey\": [}";
        AheJSONUnmarshalError e4 = assertThrows(AheJSONUnmarshalError.class, () -> a.PubKeyFromJSON(pkdeg));
        String ksdeg = "{\"keys\": [}";
        AheJSONUnmarshalError e5 = assertThrows(AheJSONUnmarshalError.class, () -> a.AttribKeysFromJSON(ksdeg));
        String ctdeg = "{\"cipher\": [}";
        AheJSONUnmarshalError e6 = assertThrows(AheJSONUnmarshalError.class, () -> a.CipherFromJSON(ctdeg));
    }


    String scheme_type2 = "fame";
    int check2 = a.SetScheme(scheme_type2);
    public void testFameLifecycle() {
        try {
            FameMasterKey masterKey = a.NewFameGenerateMasterKeys();

            String msg = "Attack at dawn!";
            String bf = "(at1 AND at2) OR at3";
            FameCipher ct = a.Encrypt(msg, bf, masterKey.pubKey);

            String[] attribs1 = new String[]{"at1", "at2"};
            FameKey key1 = a.GenAttribKeys(masterKey.secKey, attribs1);

            String pt1 = a.Decrypt(ct, key1, masterKey.pubKey);
            assertEquals(pt1, msg);

            String[] attribs2 = new String[]{"at1", "at4"};
            FameKey key2 = a.GenAttribKeys(masterKey.secKey, attribs2);

            String pt2 = a.Decrypt(ct, key2, masterKey.pubKey);
            assertEquals(pt2, null);

            String[] keys = a.GenerateSigningKeys();

            FameCipher[] cts = new FameCipher[]{ct};
            String cts_signed = a.Sign(cts, keys[1]);

            boolean check = a.Verify(cts_signed);
            assertEquals(check, true);


        } catch (Exception e) {
            fail("Unexpected exception.");
        }
    }

    // for the following test to work a key management authority should be running
    public void testFameDownloadKeys() {
        try {
            // Get public key
            URL url2 = new URL("http://91.217.255.38:6903/pubkeys");
//             URL url2 = new URL("http://localhost:6904/pubkeys");
            URLConnection con2 = url2.openConnection();
            HttpURLConnection http2 = (HttpURLConnection)con2;
            http2.setRequestMethod("GET");
            http2.connect();
            InputStream is = http2.getInputStream();
            String text2 = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            FamePubKey pubkey = new FamePubKey(text2);

            // get private key
            URL url = new URL("http://91.217.255.38:6903/get-attribute-keys");
//             URL url = new URL("http://localhost:6904/get-attribute-keys");
            URLConnection con = url.openConnection();
            HttpURLConnection http = (HttpURLConnection)con;
            http.setRequestMethod("POST");
            http.setDoOutput(true);
            byte[] out = "{\"uuid\":\"javamachine123\",\"attributes\": [\"at1\", \"at3\"]}" .getBytes(StandardCharsets.UTF_8);
            int length = out.length;
            http.setFixedLengthStreamingMode(length);
            http.setRequestProperty("Content-Type", "application/json");
            http.connect();
            OutputStream os = http.getOutputStream();
            os.write(out);
            InputStream is2 = http.getInputStream();
            String text = new String(is2.readAllBytes(), StandardCharsets.UTF_8);
            String[] parts = text.split("\n");
            FameKey key3 = new FameKey(parts);

            String msg = "Attack at dawn!";
            String bf = "(at1 AND at3) OR at2";
            FameCipher ct = a.Encrypt(msg, bf, pubkey);

            String pt1 = a.Decrypt(ct, key3, pubkey);
            assertEquals(pt1, msg);
        } catch (Exception e) {
            fail("Unexpected exception.");
        }
    }

    // for the following test to work a decentralized key management authority should be running
    public void testFameDownloadDecKeys() {
        try {
            File myObj = new File("src/com/arcadian/ahe/test/test_data/test_pubkey.txt");
            Scanner myReader = new Scanner(myObj);
            String data = myReader.nextLine();
            FamePubKey pubkey = new FamePubKey(data);

            String msg = "Attack at dawn!";
            String bf = "batman OR robin";
            FameCipher ct = a.Encrypt(msg, bf, pubkey);

            myObj = new File("src/com/arcadian/ahe/test/test_data/test_dec_keys.txt");
            myReader = new Scanner(myObj);
            data = myReader.nextLine();
            String[] rand_keys = new String[]{"40209ffc6c762019eea6205a5a984e2c42acd431b8d02f9adf951d90d10f92c3",
                    "d3143557be1a6d7239e585bb45744aec89263d8a8aa58f0fc6e8374721d8586f",
                    "1efdf3657be2eab42c1f734e248449819644036517f18709153e6d5210a343ae"};
            FameKey key3 = a.JoinDecAttribKeys(data, rand_keys);

            String pt1 = a.Decrypt(ct, key3, pubkey);
            assertEquals(pt1, msg);

        } catch (Exception e) {
            System.out.println(e.toString());
            fail("Unexpected exception.");
        }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
