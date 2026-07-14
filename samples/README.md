# TA-14 Independent Route Replay Samples

These files are synthetic demonstration packages for the public TA-14
Independent Route Replay Verifier.

## Packages

### `ta14-valid-allow.zip`

A complete signed and sealed synthetic route package. It should return:

- Overall status: `VERIFIED`
- Original decision: `ALLOW`
- Independently replayable: `YES`

### `ta14-tampered-package.zip`

The route manifest was changed after package construction. It should fail
package-integrity verification.

### `ta14-broken-ledger.zip`

The first ledger event was changed without rebuilding the hash-linked chain,
signatures, seal, or package manifest. It should fail ledger-integrity
verification.

### `ta14-wrong-signature.zip`

The included public verification key was replaced with an unrelated key while
the original signatures remained unchanged. It should fail signature-integrity
verification.

## Boundary

These files contain synthetic demonstration records only. They are not proof
of an actual financial transaction, legal approval, regulatory certification,
safety certification, production clearance, or the truth of an unauthenticated
external source.
