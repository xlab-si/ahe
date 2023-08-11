# AHE: JavaScript Bindings

## Use
The easiest way to use AHE with JS is to use WASM build of the library. To do so you need to have `he.wasm` file
that contains the build of the libray and `wasm_exec.js` file, that bridges the (Go compiled) wasm file to JS.
Both files can be found in `ahe-library/wasm` folder.

### In a web browser
Check `browser_test.html` for an example of how to load wasm into a html page. After it is loaded, one can use
functions _AheEncrypt_ and _AheDecrypt_ allowing to encrypt and decrypt using ABE scheme FAME. Also functions
_AheGenerateMasterKeys_ and _AheGenerateAttribKeys_ are available (usually run by a key management authority),
meant for testing.

### With NodeJS
Check `node_test.js` for an example of how to load wasm in a NodeJS application. After it is loaded, it offers the same
functionality as it is provided in a web browser. Run `node node_test.js` to test the code.
