// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import "testing"

func TestCheckEscrowFlags(t *testing.T) {
	tests := []struct {
		name                                   string
		kms, tpm, escrow, recipients, identity string
		wantErr                                bool
	}{
		{name: "none"},
		{name: "kms", kms: "k"},
		{name: "tpm", tpm: "t"},
		{name: "tpm escrow", tpm: "t", escrow: "e", recipients: "r"},
		{name: "recovery", escrow: "e", identity: "i"},
		{name: "escrow alone", escrow: "e", wantErr: true},
		{name: "recipients alone", recipients: "r", wantErr: true},
		{name: "identity alone", identity: "i", wantErr: true},
		{name: "escrow recipients without tpm", escrow: "e", recipients: "r", wantErr: true},
		{name: "escrow recipients with kms", kms: "k", escrow: "e", recipients: "r", wantErr: true},
		{name: "tpm recipients without escrow", tpm: "t", recipients: "r", wantErr: true},
		{name: "tpm escrow without recipients", tpm: "t", escrow: "e", wantErr: true},
		{name: "recipients and identity", tpm: "t", escrow: "e", recipients: "r", identity: "i", wantErr: true},
		{name: "recovery with tpm", tpm: "t", escrow: "e", identity: "i", wantErr: true},
		{name: "recovery with kms", kms: "k", escrow: "e", identity: "i", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkEscrowFlags(tc.kms, tc.tpm, tc.escrow, tc.recipients, tc.identity)
			if (err != nil) != tc.wantErr {
				t.Errorf("checkEscrowFlags = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
