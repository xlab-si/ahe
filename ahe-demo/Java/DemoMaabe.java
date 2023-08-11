import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpClient;
import java.net.http.HttpResponse.BodyHandlers;

import com.arcadian.ahe.Ahe;
import com.arcadian.ahe.type.MaabePubKey;
import com.arcadian.ahe.type.MaabeKey;
import com.arcadian.ahe.type.MaabeCipher;
import com.arcadian.ahe.type.Maabe;

public class DemoMaabe {
    public static final Ahe a = new Ahe();
    int check = a.SetScheme("maabe");
    public static HashMap<String,MaabePubKey> pksWallet = new HashMap<String,MaabePubKey>();
    public static HashMap<String,MaabeKey[]> ksWallet = new HashMap<String,MaabeKey[]>();

    public static MaabePubKey getAuthPubKeys(String authAddress,
                                             String authPort) {
        try {
        String url = authAddress + ":" + authPort + "/pubkeys";
        HttpRequest request = HttpRequest.newBuilder()
            .uri(new URI(url))
            .GET()
            .build();
        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            return null;
        }
        String pksJSON = response.body();
        MaabePubKey pks = a.PubKeyFromJSON(pksJSON);
        return pks;
        } catch (Exception e) {
            System.out.println(e);

            return null;
        }
    }

    public static MaabeKey[] getAuthAttributeKeys(String authAddress,
                                                String authPort,
                                                String gid,
                                                String attribs[]) {
        try {
        String url = authAddress + ":" + authPort + "/get-attribute-keys";
        String jsonStr = "{\"uuid\":\"" + gid + "\",\"attributes\":[";
        for (int i = 0; i < attribs.length; i++) {
            jsonStr = jsonStr + "\"" + attribs[i] + "\"";
            if (i != attribs.length - 1) {
                jsonStr = jsonStr + ",";
            }
        }
        jsonStr = jsonStr + "]}";
        HttpRequest request = HttpRequest.newBuilder()
            .uri(new URI(url))
            .headers("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonStr))
            .build();
        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            return null;
        }
        String ksJSON = response.body();
        MaabeKey[] ks = a.AttribKeysFromJSON(ksJSON);
        return ks;
        } catch (Exception e) {
            return null;
        }
    }

    public static void getPubKeys() {
        for (int i = 1; i <= 3; i++) {
            String address = "http://localhost";
            String port = String.valueOf(6950 + i);
            String id = "auth" + String.valueOf(i);
            pksWallet.put(id, getAuthPubKeys(address, port));
            System.out.println("Obtained public keys from " + id);
        }
    }

    public static void getAttribKeys() {
        for (int i = 1; i <= 3; i++) {
            // note that http is used, but in a real world scenario this would need to be https
            String address = "http://localhost";
            String port = String.valueOf(6950 + i);
            String id = "auth" + String.valueOf(i);
            ksWallet.put(id, getAuthAttributeKeys(address, port, "user1", new String[]{id+":test_attribute0", id+":test_attribute1"}));
            System.out.println("Obtained attribute keys from " + id);
        }
    }

    public static MaabeKey[] ksToList() {
        int len = 0;
        for (String k : ksWallet.keySet()) {
            len = len + ksWallet.get(k).length;
        }
        MaabeKey[] ksList = new MaabeKey[len];
        int i = 0;
        for (String auth : ksWallet.keySet()) {
            for (MaabeKey k : ksWallet.get(auth)) {
                ksList[i] = k;
                i++;
            }
        }
        return ksList;
    }

    public static String encryptText(String message, String policy) {
        System.out.println("Encrypting");
        if (pksWallet.isEmpty()) {
            getPubKeys();
        }
        try {
            int check = a.SetScheme("maabe");
            MaabePubKey[] pks = pksWallet.values().toArray(new MaabePubKey[0]);

            MaabeCipher ct = a.Encrypt(message, policy, pks);
            String ctJSON = a.CipherToJSON(ct);
            System.out.println("Successfully encrypted");

            return ctJSON;
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    public static void decryptText(String message) {
        System.out.println("decrypting");
        if (ksWallet.isEmpty()) {
            getAttribKeys();
        }
        try {
        MaabeCipher ct = a.CipherFromJSON(message);
        MaabeKey[] ks = ksToList();
        String pt = a.Decrypt(ct, ks);
        if (pt == null) {
            System.out.println("Could not decrypt");
            return;
        }
        System.out.println("Decrypted message:");
        System.out.println(pt);
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }


    public static void main(String argv[]) {
        System.out.println("start");
        try {
            String msg = "Attack at dawn!!";
            String bf = "(auth1:test_attribute0 OR auth2:test_attribute1)";
            String enc = encryptText(msg, bf);
            decryptText(enc);

        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }
}
