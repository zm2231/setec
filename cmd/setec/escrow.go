// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"io"
	"os"
)

// checkEscrowFlags reports an error if the escrow flags are not a complete
// set for exactly one use: escrowing a TPM-sealed key (escrowFile with
// recipients and tpmKeyFile), or recovering without the TPM (escrowFile with
// identityFile, and neither kmsKeyName nor tpmKeyFile).
func checkEscrowFlags(kmsKeyName, tpmKeyFile, escrowFile, recipients, identityFile string) error {
	switch {
	case recipients != "" && identityFile != "":
		return errors.New("--tpm-key-escrow-recipients and --escrow-identity-file are mutually exclusive")
	case (escrowFile != "") != (recipients != "" || identityFile != ""):
		return errors.New("--tpm-key-escrow-file must be given together with one of --tpm-key-escrow-recipients or --escrow-identity-file")
	case recipients != "" && tpmKeyFile == "":
		return errors.New("--tpm-key-escrow-recipients requires --tpm-key-file")
	case identityFile != "" && (kmsKeyName != "" || tpmKeyFile != ""):
		return errors.New("--escrow-identity-file cannot be combined with --kms-key-name or --tpm-key-file")
	}
	return nil
}

func readAgeFile[T any](path string, parse func(io.Reader) ([]T, error)) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parse(f)
}
