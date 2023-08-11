const fs = require('fs')

async function LoadWasm() {
    require("../wasm/wasm_exec.js")
    const go = new Go();
    const source = fs.readFileSync("../build/he.wasm");
    let typedArray = new Uint8Array(source)
    let mod, inst;

    await WebAssembly.instantiate(typedArray.buffer, go.importObject).then(
        async result => {
            mod = result.module;
            inst = result.instance;
            await go.run(inst);
        }
    )
}

LoadWasm()
// The use of setInterval is here to give time to LoadWasm to complete its job and load all the HE functions
let retry = setInterval(function () {
    test_fame()
    console.log("Fame working.")

    test_decentralized_key_join()
    console.log("Decentralized key join working.")

    clearInterval(retry);
}, 500);

async function test_fame() {
    // public key and private attribute keys should in a real scenario be obtained from the key management,
    // by a https call: see for example ahe-demo/demo_fame.go or ahe-demo/demo_fame.py
    let keys = AheGenerateMasterKeys()
    let pk = keys[0];
    let sk = keys[1]
    let ak = AheGenerateAttribKeys(sk, ["att1", "bla2"])


    let start = Date.now()
    let msg = "bla"
    let c = AheEncrypt(msg, "att1 OR att2", pk)
    console.log("Encryption time", Date.now() - start)

    start = Date.now();
    let msg2 = AheDecrypt(c, ak, pk)
    console.log("Decryption time", Date.now() - start);

    console.assert(msg2 == msg)

    keys = AheGenerateSignKeys()
    let sig_sk = keys[1]

    let ctsSigned = AheSignCiphers(sig_sk, [c.join(',')], "")

    let check = AheVerifyCiphers(ctsSigned, "", "")
    console.assert(check)

    clearInterval(retry);
}


async function test_decentralized_key_join() {
    let msg = "bla2"

    // in a real scenario, decentralized keys should be obtained from a key server, given random keys,
    // here we mock them from files
    let randKeys = ["40209ffc6c762019eea6205a5a984e2c42acd431b8d02f9adf951d90d10f92c3",
        "d3143557be1a6d7239e585bb45744aec89263d8a8aa58f0fc6e8374721d8586f",
        "1efdf3657be2eab42c1f734e248449819644036517f18709153e6d5210a343ae"]
    fs.readFile("test_data/test_dec_keys.txt", function (err, data) {
        if (err) {
            throw err;
        }
        let encKeys = data.toString()
        let decKeys = AheDecrytAttribKeys(encKeys, randKeys)
        let ak = AheJoinDecAttribKeys(decKeys)

        fs.readFile("test_data/test_pubkey.txt", function (err, data2) {
            if (err) {
                throw err;
            }
            let pk = data2.toString()
            let c = AheEncrypt(msg, "batman OR robin", pk)
            let msg2 = AheDecrypt(c, ak, pk)
            console.assert(msg2 == msg)
        });

    });
}

