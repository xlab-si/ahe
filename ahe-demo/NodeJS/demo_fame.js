const fetch = require('node-fetch');
const fs = require('fs')

// Load wasm functionality
LoadWasm()
// The use of setInterval is here to give time to LoadWasm to complete its job and load all the HE functions
let retry = setInterval(function () {
    fame_demo()
    clearInterval(retry);
}, 200);

async function fame_demo() {
    // request public ke
    let address = "http://localhost:6903"
    fetch(address + "/pubkeys").then(
        data=>{return data.text()}).then(
        pk=>{
            console.log("public key obtained")

            let msg = "test_message"
            // encrypt with obtained public key
            let c = AheEncrypt(msg, "att1 OR att2", pk)
            console.log("message encrypted")

            // request private attribute keys
            // note that we use http, but in a real-world case https should be used; see for example Go or Python FAME demo
            fetch(address + '/get-attribute-keys', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ uuid: "bla", attributes: ["att1", "bla2"]})
            })
                .then(response => response.text())
                .then(akString => {
                    let ak = akString.split("\n")
                    console.log("private attribute key obtained")

                    // decrypt with the obtained key
                    let msg2 = AheDecrypt(c, ak, pk)
                    console.assert(msg2 == msg)})
                    console.log("message decrypted")
        }
    )
}

async function LoadWasm() {
    require("../../ahe-library/wasm/wasm_exec.js")
    const go = new Go();
    const source = fs.readFileSync("../../ahe-library/prebuild/wasm/he.wasm");
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
