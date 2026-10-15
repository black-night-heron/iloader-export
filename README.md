# iloader-export

Export the certificate and private key that iLoader already uses, packaged as a `.p12` file.

## Run

```sh
iloader-export you@example.com --inspect    # dry run: report what is in storage
iloader-export you@example.com              # writes iloader.p12
iloader-export you@example.com -o <path>    # custom .p12 output path
```

## Notes

Login goes through an anisette server, by default the third-party `https://ani.jkcoxson.com` (override with `--anisette-server`). 

Use `--inspect` to look at iLoader's storage without any network access.

## Build

```sh
cargo build --release
```

## License

MIT.
