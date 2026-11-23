# SSH test vectors

No private key is committed here. The tests in `ssh_test.go` build every
private-key fixture themselves: the ed25519 key from the fixed seed
`sha256("k3sm-typed-test ed25519 fixture")` (`fixtureSeed`), unencrypted and
passphrase-encrypted with `golang.org/x/crypto/ssh`, an ECDSA P-256 key from a
fixed scalar, and an RSA key generated per run. None protects anything.

- `ed25519.pub`: the public half of the `fixtureSeed` key, comment
  `k3sm-typed-test`, written by `typed.SSHAuthorizedKey` on 2026-11-22.
- `ed25519.ssh-keygen-l`: `ssh-keygen -l -E sha256 -f ed25519.pub`, verbatim,
  from OpenSSH_10.5p1 (LibreSSL 3.3.6). `TestSSHFingerprintMatchesOpenSSH`
  checks that importing the in-test private key of the same seed yields it.
- `ed25519-cert.pub`: `ed25519.pub` signed by a discarded CA key,
  `ssh-keygen -s ca -I k3sm-test -n k3sm`.
