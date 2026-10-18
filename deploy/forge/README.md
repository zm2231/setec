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
encrypted to your YubiKey (`age-plugin-yubikey`). The server saves
`state/setec-tpm.key.age` before it saves a new sealed key file; copy that
file off forge once. It never changes.

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

Recovery needs the latest database backup, `setec-tpm.key.age`, and the escrow
identity decrypted with the YubiKey. It runs without a TPM, so it does not use
this compose file, whose TPM key, recipients, and device settings conflict
with recovery. On the recovery machine, with the image built from this fork:

```
mkdir -p state && cp <database backup> state/database
cp setec-tpm.key.age state/
age -d -i <yubikey identity> setec-escrow-identity.age > escrow-identity.txt
sudo chown -R 65532:65532 state && chmod 0700 state

docker run -d --name setec --restart unless-stopped --user 65532:65532 \
  -v "$PWD/state:/state" \
  -v "$PWD/escrow-identity.txt:/config/escrow-identity.txt:ro" \
  -e SETEC_STATE_DIR=/state -e SETEC_HOSTNAME=secrets \
  -e SETEC_TPM_KEY_ESCROW_FILE=/state/setec-tpm.key.age \
  -e SETEC_ESCROW_IDENTITY_FILE=/config/escrow-identity.txt \
  -e TS_AUTHKEY=<new tagged auth key> \
  setec:<commit>
```

`escrow-identity.txt` is the plaintext escrow identity; keep it only on the
recovery machine, readable by uid 65532, for as long as recovery mode runs.
Remove the old `secrets` node from the tailnet first, or the new node joins
under another name.
