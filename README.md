This library provides wasm bindings for signing under the `sig/wasm.rs` module. These can be built
via the [`wasm-pack`](https://github.com/rustwasm/wasm-pack) tool. Depending on the platform you are 
targetting, you'll need to use a different build flag. In order to see this in practice, look at the example
under [`examples/blind.js`](./examples/blind.js). You can run it yourself by executing the following commands.

```
$ wasm-pack build --target nodejs -- --features=wasm
$ node examples/blind.js
$ node examples/tblind.js
```
