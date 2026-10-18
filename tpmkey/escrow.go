// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tpmkey

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tink-crypto/tink-go/v2/tink"
	"tailscale.com/atomicfile"
)

// OpenOrCreateEscrowed is like [OpenOrCreate], but also keeps a copy of the
// key in the file at escrowPath, encrypted with age to recipients, so that
// the key can be recovered with [OpenEscrow] without the TPM.
//
// For a new key, the escrow copy is saved before the sealed key, so a sealed
// key never exists without one. For an existing sealed key, a missing escrow
// copy is written after unsealing; an existing escrow copy is left untouched.
//
// If the escrow file exists but the sealed key file does not, it reports an
// error rather than generate a new key, since the escrow file may hold the
// only remaining copy of a key that still protects a database.
func OpenOrCreateEscrowed(tpm transport.TPM, path, escrowPath string, recipients []age.Recipient) (tink.AEAD, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no escrow recipients")
	}
	escrowExists, err := fileExists(escrowPath)
	if err != nil {
		return nil, err
	}
	sealedExists, err := fileExists(path)
	if err != nil {
		return nil, err
	}
	if escrowExists && !sealedExists {
		return nil, fmt.Errorf("escrow file %q exists but sealed key file %q does not; recover the key with the escrow identity instead of generating a new one", escrowPath, path)
	}

	var escrow func([]byte) error
	if !escrowExists {
		escrow = func(secret []byte) error {
			return writeEscrow(escrowPath, secret, recipients)
		}
	}
	secret, err := openOrCreate(tpm, path, escrow)
	if err != nil {
		return nil, err
	}
	return newAEAD(secret)
}

// OpenEscrow returns a [tink.AEAD] keyed by the escrow copy in the file at
// escrowPath, decrypted with one of identities. The result can decrypt
// anything encrypted with the AEAD from [OpenOrCreateEscrowed].
func OpenEscrow(escrowPath string, identities []age.Identity) (tink.AEAD, error) {
	bs, err := os.ReadFile(escrowPath)
	if err != nil {
		return nil, fmt.Errorf("reading escrow file: %w", err)
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(bs)), identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypting escrow file %q: %w", escrowPath, err)
	}
	secret, err := io.ReadAll(io.LimitReader(r, keySize+1))
	if err != nil {
		return nil, fmt.Errorf("decrypting escrow file %q: %w", escrowPath, err)
	}
	return newAEAD(secret)
}

func writeEscrow(path string, secret []byte, recipients []age.Recipient) error {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipients...)
	if err != nil {
		return fmt.Errorf("encrypting escrow copy: %w", err)
	}
	if _, err := w.Write(secret); err != nil {
		return fmt.Errorf("encrypting escrow copy: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("encrypting escrow copy: %w", err)
	}
	if err := aw.Close(); err != nil {
		return fmt.Errorf("encrypting escrow copy: %w", err)
	}
	if err := atomicfile.WriteFile(path, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("writing escrow file: %w", err)
	}
	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	} else if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}
