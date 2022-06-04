# sealcheck

CLI utility for checking [Planet](https://planet.ink) seal proofs. [Documentation](https://docs.planet.ink/data/seal/)

*Seal* is a mechanism for cryptographically proving that a note is created before a specific time.

Seal works by periodically rolling up Planet's event log into a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) and submitting the root of the tree to the [Certificate Transparency](https://certificate.transparency.dev/) public ledger by requesting a certificate for the domain name `[root-hash].production.planet-seal.net`. Once the proof for a note is generated, you can download it through the "Seal" entry in the note menu.

## Usage

```
$ ./sealcheck validate ./seal_proof.json
SealCheck: ./seal_proof.json
Validation OK. Certificate issued at 2022-06-01 01:12:23 +0000 UTC.
```
