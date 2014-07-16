package dcrypt

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/marcopeereboom/mcrypt"
)

var (
	pj     []byte          // Payload json
	ssJson []byte          // Shared Secrets json
	ss     *SharedSecret   // Shared Secrets used to encrypt payload
	msg    *mcrypt.Message // Encrypted payload

	alice, bob, charlie *mcrypt.Identity
)

func TestPayload(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "payload")
	if err != nil {
		t.Error(err)
		return
	}
	f.Close()

	data := strings.Repeat("This is an awesome payload", 200)
	err = ioutil.WriteFile(f.Name(), []byte(data), 0600)
	if err != nil {
		t.Error(err)
		return
	}

	// generate payload structure
	p, err := NewPayload(f.Name(), "Describe payload", true)
	if err != nil {
		t.Error(err)
		return
	}

	// make json
	pj, err = p.Marshal()
	if err != nil {
		t.Error(err)
		return
	}

	// make new struct from json
	pp, err := NewPayloadFromJson(pj, false)
	if err != nil {
		t.Error(err)
		return
	}

	// make sure payload is the same
	if !reflect.DeepEqual(pp, p) {
		t.Errorf("payload corrupt")
		return
	}

	// test decompression
	pc, err := NewPayloadFromJson(pj, true)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(pc.Payload, []byte(data)) {
		t.Errorf("decompression failed")
		return
	}
}

func TestEncrypt(t *testing.T) {
	var err error
	ss, err = NewSharedSecret("", "")
	if err != nil {
		t.Error(err)
		return
	}
	msg, err = ss.Encrypt(pj)
	if err != nil {
		t.Error(err)
		return
	}

	// decrypt
	j, err := ss.Decrypt(msg)
	if err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(j, pj) {
		t.Errorf("corrupted encryption/decryption")
		return
	}
}

func TestMulti(t *testing.T) {
	var err error
	alice, err = mcrypt.NewIdentity("Alice", "alice@localhost")
	if err != nil {
		t.Error(err)
		return
	}
	bob, err = mcrypt.NewIdentity("Bob", "bob@localhost")
	if err != nil {
		t.Error(err)
		return
	}
	charlie, err = mcrypt.NewIdentity("Charlie", "charlie@localhost")
	if err != nil {
		t.Error(err)
		return
	}

	to := []mcrypt.PublicIdentity{
		alice.PublicIdentity,
		bob.PublicIdentity,
		charlie.PublicIdentity,
	}

	// marshal shared secrets
	ssJson, err = json.Marshal(ss)
	if err != nil {
		t.Error(err)
		return
	}

	// encrypt shared secrets to everyone
	j, err := NewEncryptedRecipients(alice, to, ssJson)
	if err != nil {
		t.Error(err)
		return
	}

	// decrypt
	newSharedSecret1, err := SharedSecretFromRecipient(alice,
		&alice.PublicIdentity, j)
	if err != nil {
		t.Error(err)
		return
	}
	newSharedSecret2, err := SharedSecretFromRecipient(bob,
		&alice.PublicIdentity, j)
	if err != nil {
		t.Error(err)
		return
	}
	newSharedSecret3, err := SharedSecretFromRecipient(charlie,
		&alice.PublicIdentity, j)
	if err != nil {
		t.Error(err)
		return
	}

	// negative test
	_, err = SharedSecretFromRecipient(charlie,
		&bob.PublicIdentity, j)
	if err == nil {
		t.Errorf("charlie did not send shared secrets")
		return
	}

	// make sure everyone is the same
	if !bytes.Equal(newSharedSecret1.Identity.Key[:],
		newSharedSecret2.Identity.Key[:]) {
		t.Errorf("shared secret corrupt")
		return
	}

	if !bytes.Equal(newSharedSecret1.Identity.Key[:],
		newSharedSecret3.Identity.Key[:]) {
		t.Errorf("shared secret corrupt")
		return
	}

	// try decrypting msg
	fromAlice, err := newSharedSecret3.Decrypt(msg)
	if err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(fromAlice, pj) {
		t.Errorf("corrupted encryption/decryption")
		return
	}

	t.Logf("fromAlice %s", fromAlice)
}
