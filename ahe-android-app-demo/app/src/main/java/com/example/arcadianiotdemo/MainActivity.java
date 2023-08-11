package com.example.arcadianiotdemo;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.EditText;

import com.arcadian.ahe.Ahe;
import com.arcadian.ahe.type.FameCipher;
import com.arcadian.ahe.type.FameKey;
import com.arcadian.ahe.type.FamePubKey;

import java.net.URL;
import java.net.URLConnection;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.io.OutputStream;
import java.io.InputStream;
import java.util.Scanner;

import android.os.StrictMode;


public class MainActivity extends AppCompatActivity {

    public static final String EXTRA_MSG = "com.example.arcadianiotdemo.MESSAGE";
    public static final String EXTRA_POL = "com.example.arcadianiotdemo.POLICY";
    public static Ahe a = new Ahe();


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void sendMessage(View view) {
        Intent intent = new Intent(
                this,
                DisplayMessageActivity.class);
        EditText editTextMsg = (EditText) findViewById(R.id.editTextTextPersonName);
        EditText editTextPol = (EditText) findViewById(R.id.editTextTextPersonName2);
        String msg = editTextMsg.getText().toString();
        String policy = editTextPol.getText().toString();
        String cts_signed = "", bf = "";
        a.SetScheme("fame");

        // a hack to allow http calls (in further versions it will be a https call)
        StrictMode.ThreadPolicy policy1 = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy1);
        try {
            // Get public key (in a real scenario, this would be done at the registration);
            // note that this is done via http, while in a real-world scenario https should be
            // used; see Go or Python demo for an example
            URL url = new URL("http://10.0.2.2:6903/pubkeys");
            URLConnection con = url.openConnection();
            HttpURLConnection http = (HttpURLConnection)con;
            http.setRequestMethod("GET");
            http.connect();
            InputStream is = http.getInputStream();
            Scanner s = new Scanner(is).useDelimiter("\\A");
            String pubKeyString = s.hasNext() ? s.next() : "";
            FamePubKey pubKey = new FamePubKey(pubKeyString);

            // encrypt the msg with specified policy or the default one
            bf = policy.equals("") ? "(at1 AND at3) OR at2" : policy;
            FameCipher ct = a.Encrypt(msg, bf, pubKey);
            String del = ",";
            String ctStr = TextUtils.join(del, ct.toStringList());

            // to sign the ciphertext first create signing keys
            String[] keys = a.GenerateSigningKeys();
            String pk = keys[0];
            String sk = keys[1];
            // post your public signature verification key on the key management and receive
            // a proof of it
            url = new URL("http://10.0.2.2:6903/pub-signature-keys");
            con = url.openConnection();
            http = (HttpURLConnection)con;
            http.setRequestMethod("POST");
            http.setDoOutput(true);
            byte[] out = ("{\"uuid\":\"javamachine123\",\"verkey\":\"" + pk +"\"}").getBytes(StandardCharsets.UTF_8);
            int length = out.length;
            http.setFixedLengthStreamingMode(length);
            http.setRequestProperty("Content-Type", "application/json");
            http.connect();
            OutputStream os = http.getOutputStream();
            os.write(out);
            is = http.getInputStream();
            s = new Scanner(is).useDelimiter("\\A");
            String proof = s.hasNext() ? s.next() : "";

            // create an array of the ciphertexts and sign them;
            // the result is a string that can be sent or stored
            FameCipher[] cts = new FameCipher[]{ct};
            cts_signed = a.Sign(cts, sk, proof);

            // verify the correctness of the signature
            // first load CA cert
            is = getApplicationContext().getAssets().open("HEkeyCA.crt");
            s = new Scanner(is).useDelimiter("\\A");
            String ca = s.hasNext() ? s.next() : "";
            // check that the data was signed by "javamachine123" (CA guarantees the authenticity)
            boolean check = a.Verify(cts_signed, "javamachine123", ca);
            System.out.println("signature correctness: " + check);

            // just for test, try to decrypt your own message
            // get private key
            url = new URL("http://10.0.2.2:6903/get-attribute-keys");
            con = url.openConnection();
            http = (HttpURLConnection)con;
            http.setRequestMethod("POST");
            http.setDoOutput(true);
            // attribute set is [at1, at3]
            out = "{\"uuid\":\"javamachine123\",\"attributes\": [\"at1\", \"at3\"]}".getBytes(StandardCharsets.UTF_8);
            length = out.length;
            http.setFixedLengthStreamingMode(length);
            http.setRequestProperty("Content-Type", "application/json");
            http.connect();
            os = http.getOutputStream();
            os.write(out);
            is = http.getInputStream();
            s = new Scanner(is).useDelimiter("\\A");
            String text = s.hasNext() ? s.next() : "";
            String[] parts = text.split("\n");
            FameKey key = new FameKey(parts);
            // decrypt the message
            String pt = a.Decrypt(ct, key, pubKey);
            System.out.println("Try to decrypt your own message, having attributes [at1, at3]:");
            System.out.println(pt);

        } catch (Exception e) {
            System.out.println(e);
            System.out.println("Unexpected exception!!!");
        }
        intent.putExtra(EXTRA_MSG, cts_signed);
        intent.putExtra(EXTRA_POL, policy.equals("") ? bf : policy);
        startActivity(intent);
    }
}