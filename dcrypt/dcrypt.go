package dcrypt

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/marcopeereboom/mcrypt"
)

// Public Key is known to recipients
type AnonHeader struct {
	Nonce []byte // nonce to decrypt recipients
}

type Header struct {
	PublicIdentity mcrypt.PublicIdentity
	Nonce          []byte // nonce to decrypt recipients
	Signature      []byte // signature of nonce
}

type Recipients struct {
	PublicIdentities []mcrypt.Message
}

func NewEncryptedRecipients(from *mcrypt.Identity,
	to []mcrypt.PublicIdentity,
	payload []byte) ([]byte, error) {
	r := Recipients{
		PublicIdentities: make([]mcrypt.Message, 0, len(to)),
	}
	for _, v := range to {
		m, err := from.Encrypt(v.Key, payload)
		if err != nil {
			return nil, err
		}
		r.PublicIdentities = append(r.PublicIdentities, *m)
	}

	j, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	return j, nil
}

// SharedSecret is what is used to encrypt Payload.
// All recipients will be able to decrypt this.
type SharedSecret struct {
	Identity mcrypt.Identity
}

func SharedSecretFromRecipient(me *mcrypt.Identity,
	them *mcrypt.PublicIdentity,
	payload []byte) (*SharedSecret, error) {
	r := Recipients{}
	err := json.Unmarshal(payload, &r)
	if err != nil {
		return nil, err
	}
	for _, v := range r.PublicIdentities {
		ssJson, err := me.Decrypt(them.Key, &v)
		if err != nil {
			continue
		}
		ss := SharedSecret{}
		err = json.Unmarshal(ssJson, &ss)
		if err != nil {
			fmt.Printf("ERR %v\n", err)
			return nil, err
		}
		return &ss, nil
	}

	return nil, fmt.Errorf("not for you")
}

// Generate a shared secret identity to encrypt Payload.
func NewSharedSecret(name, address string) (*SharedSecret, error) {
	id, err := mcrypt.NewIdentity(name, address)
	if err != nil {
		return nil, err
	}
	ss := SharedSecret{
		Identity: *id,
	}
	return &ss, nil
}

func (s *SharedSecret) Encrypt(payload []byte) (*mcrypt.Message, error) {
	return s.Identity.Encrypt(s.Identity.PublicIdentity.Key, payload)
}

func (s *SharedSecret) Decrypt(m *mcrypt.Message) ([]byte, error) {
	return s.Identity.Decrypt(s.Identity.PublicIdentity.Key, m)
}

// payload stuff
const (
	compressionZlib = "zlib"
)

type Payload struct {
	Basename    string
	Description string
	Compression string
	Mime        string
	Payload     []byte
}

func (p *Payload) Marshal() ([]byte, error) {
	j, err := json.Marshal(*p)
	if err != nil {
		return nil, err
	}
	return j, nil
}

func NewPayload(filename, description string, compress bool) (*Payload, error) {
	payload, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	p := Payload{
		Basename:    path.Base(filename),
		Description: description,
		Mime:        http.DetectContentType(payload),
		Payload:     payload,
	}

	if compress {
		// try compressing it
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write(payload)
		w.Close()
		if b.Len() < len(payload) {
			p.Compression = compressionZlib
			p.Payload = b.Bytes()
		}
	}

	return &p, nil
}

func NewPayloadFromJson(j []byte, decompress bool) (*Payload, error) {
	p := Payload{}
	err := json.Unmarshal(j, &p)
	if err != nil {
		return nil, err
	}

	if decompress && p.Compression == compressionZlib {
		b := bytes.NewReader(p.Payload)
		r, err := zlib.NewReader(b)
		if err != nil {
			return nil, err
		}
		newPayload, err := ioutil.ReadAll(r)
		p.Payload = newPayload
		r.Close()
		p.Compression = ""
	}

	return &p, nil
}
