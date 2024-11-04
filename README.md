# `pwsec` - support for password-based encryption

[![Latest version](https://img.shields.io/crates/v/pwsec.svg)](https://crates.io/crates/pwsec)
[![Documentation](https://docs.rs/pwsec/badge.svg)](https://docs.rs/pwsec)
[![License](https://img.shields.io/crates/l/pwsec.svg)](https://github.com/emabee/pwsec)
[![Build](https://img.shields.io/github/actions/workflow/status/emabee/pwsec/ci_test.yml?branch=main)](https://github.com/emabee/pwsec/actions?query=workflow%3ACI)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

## Usage

Add `pwsec` to the dependencies section in your project's `Cargo.toml`:

```toml
[dependencies]
pwsec = "0.5"
```

## Capabilities

`pwsec` uses an (optionally authenticated) encryption scheme.

Two closely related variants are provided currently, `Chacha` and `ChachaB64`.

Alternative variants with similar API and based on other encryption algorithms can be added on demand.

## Example with `ChachaB64` and storage in a file

### Encryption

```mermaid
flowchart LR

A1{{Auth data}}
A2[/Auth data/]
C[/CipherB64:
salt+ciphertext+nonce/]
E[__ChachaB64::__
__encrypt_auth__
]
P{{Password}}
S{{Secret}}

style E fill:#AAf,stroke:#333,stroke-width:3px

subgraph File
    C
    A2
end

subgraph Application Data
    A1
    S
end
P

P --> E
S -- Serialization --> E
A1 -- Serialization --> E

E --> C
A1 -. Serialization .-> A2
```

### Decryption

```mermaid
flowchart RL

A1{{Auth data}}
A2[/Auth data/]
C[/CipherB64:
salt+ciphertext+nonce/]
D[__ChachaB64::
decrypt_auth__]
P{{Password}}
S{{Secret}}

style D fill:#AAf,stroke:#333,stroke-width:3px

subgraph File
    C
    A2
end

subgraph Application Data
    A1
    S
end
P

P --> D
D -- Deserialization --> S
A2 --> D

C --> D
A2 -. Deserialization .-> A1
```

## Versions

See the change log for more details.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license

at your option.
