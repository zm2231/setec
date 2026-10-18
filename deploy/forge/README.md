# setec on forge

setec runs in Docker on the forge host and joins the tailnet as its own node,
`secrets`, so it has no published ports. Its database key is sealed to forge's
TPM, with an age-encrypted escrow copy for recovery without the TPM.

## Layout

```
/srv/setec/
  compose.yaml               this directory's compose.yaml
  .env                       SETEC_COMMIT=<sha>, TSS_GID=<gid of tss>
  src/                       checkout of this fork at SETEC_COMMIT
  escrow-recipients.txt      age recipient(s), one per line
  authkey.env                TS_AUTHKEY=... for the first start only
  backup.env                 optional S3-compatible backup settings
  state/                     owned by 65532:65532, mode 0700
```

## Escrow recipient

The recipient is a native X25519 age key (`age1...`). Generate it on a
machine you trust, keep only the public line here, and store the identity
encrypted to your YubiKey (`age-plugin-yubikey`). The server writes
`state/setec-tpm.key.age` before it seals a new key; copy that file off forge
once. It never changes.

## Backups

setec's built-in backup uploads the encrypted database to S3. Any
S3-compatible store works through the AWS SDK's environment settings:

```
SETEC_BACKUP_BUCKET=...
AWS_ENDPOINT_URL=https://<account>.r2.cloudflarestorage.com
SETEC_BACKUP_BUCKET_REGION=auto
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

## Recovery

With the database backup, `setec-tpm.key.age`, and the decrypted escrow
identity, start the server on any machine with `--tpm-key-escrow-file` and
`--escrow-identity-file` in place of `--tpm-key-file`.
