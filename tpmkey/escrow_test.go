// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tpmkey_test

import (
	"bytes"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/tink-crypto/tink-go/v2/tink"

	"github.com/tailscale/setec/acl"
	"github.com/tailscale/setec/audit"
	"github.com/tailscale/setec/db"
	"github.com/tailscale/setec/tpmkey"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generating age identity: %v", err)
	}
	return id
}

func checkSameKey(t *testing.T, a, b tink.AEAD) {
	t.Helper()
	plaintext := []byte("hello, world")
	context := []byte("test context")
	ciphertext, err := a.Encrypt(plaintext, context)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := b.Decrypt(ciphertext, context)
	if err != nil {
		t.Fatalf("Decrypt with other key: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt = %q, want %q", got, plaintext)
	}
}

func TestEscrowNewKey(t *testing.T) {
	tpm := newSimulatedTPM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tpm-sealed.key")
	escrowPath := filepath.Join(dir, "tpm-sealed.key.age")
	id := newIdentity(t)

	sealed, err := tpmkey.OpenOrCreateEscrowed(tpm, path, escrowPath, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatalf("OpenOrCreateEscrowed (create): %v", err)
	}
	for _, p := range []string{path, escrowPath} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if mode := fi.Mode().Perm(); mode != 0600 {
			t.Errorf("%s has mode %o, want 0600", p, mode)
		}
	}

	recovered, err := tpmkey.OpenEscrow(escrowPath, []age.Identity{id})
	if err != nil {
		t.Fatalf("OpenEscrow: %v", err)
	}
	checkSameKey(t, sealed, recovered)
	checkSameKey(t, recovered, sealed)

	escrowBefore, err := os.ReadFile(escrowPath)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := tpmkey.OpenOrCreateEscrowed(tpm, path, escrowPath, []age.Recipient{newIdentity(t).Recipient()})
	if err != nil {
		t.Fatalf("OpenOrCreateEscrowed (reopen): %v", err)
	}
	checkSameKey(t, sealed, reopened)
	escrowAfter, err := os.ReadFile(escrowPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(escrowBefore, escrowAfter) {
		t.Error("reopening rewrote an existing escrow file")
	}
}

func TestEscrowExistingKey(t *testing.T) {
	tpm := newSimulatedTPM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tpm-sealed.key")
	escrowPath := filepath.Join(dir, "tpm-sealed.key.age")
	id := newIdentity(t)

	plain, err := tpmkey.OpenOrCreate(tpm, path)
	if err != nil {
		t.Fatalf("OpenOrCreate: %v", err)
	}
	if _, err := tpmkey.OpenOrCreateEscrowed(tpm, path, escrowPath, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatalf("OpenOrCreateEscrowed: %v", err)
	}
	recovered, err := tpmkey.OpenEscrow(escrowPath, []age.Identity{id})
	if err != nil {
		t.Fatalf("OpenEscrow: %v", err)
	}
	checkSameKey(t, plain, recovered)
}

func TestEscrowWithoutSealedKey(t *testing.T) {
	tpm := newSimulatedTPM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tpm-sealed.key")
	escrowPath := filepath.Join(dir, "tpm-sealed.key.age")
	id := newIdentity(t)

	if _, err := tpmkey.OpenOrCreateEscrowed(tpm, path, escrowPath, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatalf("OpenOrCreateEscrowed (create): %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	escrowBefore, err := os.ReadFile(escrowPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tpmkey.OpenOrCreateEscrowed(tpm, path, escrowPath, []age.Recipient{id.Recipient()}); err == nil {
		t.Fatal("OpenOrCreateEscrowed generated a new key over an existing escrow file")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("sealed key file was recreated: %v", err)
	}
	escrowAfter, err := os.ReadFile(escrowPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(escrowBefore, escrowAfter) {
		t.Error("escrow file was modified")
	}
}

func TestEscrowWrongIdentity(t *testing.T) {
	tpm := newSimulatedTPM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tpm-sealed.key")
	escrowPath := filepath.Join(dir, "tpm-sealed.key.age")

	if _, err := tpmkey.OpenOrCreateEscrowed(tpm, path, escrowPath, []age.Recipient{newIdentity(t).Recipient()}); err != nil {
		t.Fatalf("OpenOrCreateEscrowed: %v", err)
	}
	if _, err := tpmkey.OpenEscrow(escrowPath, []age.Identity{newIdentity(t)}); err == nil {
		t.Error("OpenEscrow with the wrong identity unexpectedly succeeded")
	}
}

func TestEscrowNoRecipients(t *testing.T) {
	tpm := newSimulatedTPM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tpm-sealed.key")

	if _, err := tpmkey.OpenOrCreateEscrowed(tpm, path, filepath.Join(dir, "escrow.age"), nil); err == nil {
		t.Fatal("OpenOrCreateEscrowed with no recipients unexpectedly succeeded")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("sealed key file was created without an escrow copy: %v", err)
	}
}

func TestEscrowWriteFailure(t *testing.T) {
	tpm := newSimulatedTPM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tpm-sealed.key")
	escrowPath := filepath.Join(dir, "missing-dir", "escrow.age")

	if _, err := tpmkey.OpenOrCreateEscrowed(tpm, path, escrowPath, []age.Recipient{newIdentity(t).Recipient()}); err == nil {
		t.Fatal("OpenOrCreateEscrowed unexpectedly succeeded without writing an escrow copy")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("sealed key file was created without an escrow copy: %v", err)
	}
}

func TestEscrowRestoresDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tpm-sealed.key")
	escrowPath := filepath.Join(dir, "tpm-sealed.key.age")
	dbPath := filepath.Join(dir, "database")
	id := newIdentity(t)
	caller := db.Caller{
		Principal:   audit.Principal{User: "test", IP: netip.MustParseAddr("100.64.0.1"), Hostname: "test"},
		Permissions: acl.Rules{{Action: []acl.Action{acl.ActionGet, acl.ActionPut}, Secret: []acl.Secret{"*"}}},
	}

	tpm := newSimulatedTPM(t)
	sealed, err := tpmkey.OpenOrCreateEscrowed(tpm, path, escrowPath, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatalf("OpenOrCreateEscrowed: %v", err)
	}
	orig, err := db.Open(db.Config{Path: dbPath, AccessKey: sealed, AuditLog: audit.NewWriter(io.Discard)})
	if err != nil {
		t.Fatalf("db.Open with sealed key: %v", err)
	}
	if _, err := orig.Put(caller, "agents/token", []byte("s3cret")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	tpm.Close()

	recovered, err := tpmkey.OpenEscrow(escrowPath, []age.Identity{id})
	if err != nil {
		t.Fatalf("OpenEscrow: %v", err)
	}
	restored, err := db.Open(db.Config{Path: dbPath, AccessKey: recovered, AuditLog: audit.NewWriter(io.Discard)})
	if err != nil {
		t.Fatalf("db.Open with escrowed key: %v", err)
	}
	got, err := restored.Get(caller, "agents/token")
	if err != nil {
		t.Fatalf("Get after restore: %v", err)
	}
	if string(got.Value) != "s3cret" {
		t.Errorf("restored value = %q, want %q", got.Value, "s3cret")
	}

	if _, err := tpmkey.OpenOrCreate(newSimulatedTPM(t), path); err == nil {
		t.Error("sealed key unexpectedly opened on a different TPM")
	}
}

func TestEscrowSamePath(t *testing.T) {
	tpm := newSimulatedTPM(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tpm-sealed.key")
	link := filepath.Join(dir, "linked.key")
	recipients := []age.Recipient{newIdentity(t).Recipient()}

	if _, err := tpmkey.OpenOrCreateEscrowed(tpm, path, path, recipients); err == nil {
		t.Fatal("OpenOrCreateEscrowed with identical paths unexpectedly succeeded")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a file was created at the shared path: %v", err)
	}

	if _, err := tpmkey.OpenOrCreate(tpm, path); err != nil {
		t.Fatalf("OpenOrCreate: %v", err)
	}
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, escrowPath := range []string{path, filepath.Join(dir, ".", "tpm-sealed.key"), link} {
		if _, err := tpmkey.OpenOrCreateEscrowed(tpm, path, escrowPath, recipients); err == nil {
			t.Errorf("OpenOrCreateEscrowed with escrow path %q naming the sealed key file unexpectedly succeeded", escrowPath)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("sealed key file was modified")
	}
}

func TestOpenEscrowMalformed(t *testing.T) {
	dir := t.TempDir()
	id := newIdentity(t)
	escrowPath := filepath.Join(dir, "escrow.age")

	if _, err := tpmkey.OpenEscrow(filepath.Join(dir, "missing.age"), []age.Identity{id}); err == nil {
		t.Error("OpenEscrow of a missing file unexpectedly succeeded")
	}
	if err := os.WriteFile(escrowPath, []byte("not an age file"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := tpmkey.OpenEscrow(escrowPath, []age.Identity{id}); err == nil {
		t.Error("OpenEscrow of a non-age file unexpectedly succeeded")
	}

	for _, size := range []int{0, 31, 33} {
		var buf bytes.Buffer
		w, err := age.Encrypt(&buf, id.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(make([]byte, size)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(escrowPath, buf.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := tpmkey.OpenEscrow(escrowPath, []age.Identity{id}); err == nil {
			t.Errorf("OpenEscrow of a %d-byte key unexpectedly succeeded", size)
		}
	}
}
