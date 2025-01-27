## X.509 tool

Compile binary:
```
$ cargo build
```

Print available commands and options:
```
$ ./target/debug/x509_tool --help
X.509 tool for operations like:
- parse and print certificate on stdout
- render certificate or private key fields to static C-header

Usage: x509_tool <COMMAND>

Commands:
  parse   Parse and print given certificate
  render  Render given certificate to C-header
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

#### Contact

email: kamkie1996@gmail.com
