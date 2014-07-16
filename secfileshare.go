package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/marcopeereboom/mcrypt"
	"github.com/marcopeereboom/secfileshare/dcrypt"
)

var (
	dir         string
	inFilename  string
	outFilename string
	decrypt     bool
	identity    *mcrypt.Identity
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	help := false
	whoami := false

	flag.StringVar(&inFilename, "in", "", "filename that will be "+
		"encrypted/decrypted")
	flag.StringVar(&outFilename, "out", "", "filename that will be "+
		"written out, when empty the system will guess based on the "+
		"mode of operation")
	flag.BoolVar(&decrypt, "decrypt", false, "decrypt filename specified in -in")
	flag.BoolVar(&decrypt, "d", false, "shorthand for -decrypt")
	flag.BoolVar(&help, "h", false, "help")
	flag.BoolVar(&whoami, "whoami", false, "print identity information")
	flag.BoolVar(&whoami, "w", false, "shorthand for -whoami")
	flag.Parse()

	if help {
		flag.PrintDefaults()
		return
	}

	err := setup()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if whoami {
		printIdentity()
		return
	}

	err = _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func _main() error {
	if inFilename == "" {
		return fmt.Errorf("must provide an in filename")
	}

	if len(flag.Args()) == 0 {
		return fmt.Errorf("must provide recipient public keys")
	}

	if decrypt {
		if len(flag.Args()) != 1 {
			return fmt.Errorf("you can only specify one " +
				"public identity key")
		}
	}

	if decrypt {
		// do nothing for now
	} else {
		if outFilename == "" {
			outFilename = inFilename + ".sfs"
		}
	}

	if outFilename != "" {
		// see if target file exists
		_, err := os.Stat(outFilename)
		if err == nil {
			return fmt.Errorf("target file already exists")
		}
	}

	pk, err := parsePublicKeys()
	if err != nil {
		return fmt.Errorf("invalid public key %v\n", err)
	}

	if decrypt {
		err = decodeFile(pk)
	} else {
		err = encodeFile(pk)
	}
	if err != nil {
		return err
	}

	return nil
}

func printIdentity() {
	fmt.Printf("Name        : %v\n",
		identity.PublicIdentity.Name)
	fmt.Printf("Address     : %v\n",
		identity.PublicIdentity.Address)
	fmt.Printf("Public key  : %x\n",
		*identity.PublicIdentity.Key)
	fmt.Printf("Fingerprint : %v\n",
		identity.PublicIdentity.Fingerprint())
}

func setup() error {
	// setup paths
	usr, err := user.Current()
	if err != nil {
		return err
	}
	dir = usr.HomeDir + homeDir
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return err
	}

	// test to see if we have an identity
	if identityExists() == false {
		host, err := os.Hostname()
		if err != nil {
			return err
		}

		usr, err := user.Current()
		if err != nil {
			return err
		}

		identity, err = mcrypt.NewIdentity(usr.Name,
			usr.Username+"@"+host)
		if err != nil {
			return err
		}

		err = identitySave()
		if err != nil {
			return err
		}

		fmt.Printf("inital run, creating identity in %v\n",
			dir+identityFilename)
		printIdentity()
	}

	err = identityOpen()
	if err != nil {
		return err
	}

	return nil
}

func parsePublicKeys() ([]mcrypt.PublicIdentity, error) {
	rv := make([]mcrypt.PublicIdentity, 0, len(flag.Args()))

	for i, v := range flag.Args() {
		v = strings.ToLower(v)
		v = strings.TrimPrefix(v, "0x")
		pk, err := hex.DecodeString(v)
		if err != nil {
			return nil, err
		}
		if len(pk) != 32 {
			return nil, fmt.Errorf("invalid public key number %v "+
				"value %v", i+1, v)
		}
		key := mcrypt.PublicIdentity{
			Key: &[32]byte{},
		}
		copy(key.Key[:], pk)
		rv = append(rv, key)
	}

	return rv, nil
}

func encodeFile(to []mcrypt.PublicIdentity) error {
	// read file and generate payload structure
	p, err := dcrypt.NewPayload(inFilename, "Describe payload", true)
	if err != nil {
		return err
	}

	// make json
	pj, err := p.Marshal()
	if err != nil {
		return err
	}

	// encrypt payload with shared key
	ss, err := dcrypt.NewSharedSecret("", "")
	if err != nil {
		return err
	}
	msg, err := ss.Encrypt(pj)
	if err != nil {
		return err
	}
	msgJson, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// encrypt shared key to other parties
	ssJson, err := json.Marshal(ss)
	if err != nil {
		return err
	}

	// encrypt shared secrets to everyone
	j, err := dcrypt.NewEncryptedRecipients(identity, to, ssJson)
	if err != nil {
		return err
	}

	// write out bits
	f, err := os.OpenFile(outFilename,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\n%s\n", j, msgJson)

	return nil
}

func decodeFile(to []mcrypt.PublicIdentity) error {
	f, err := os.Open(inFilename)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)

	// read shared secrets
	ssJson, err := r.ReadBytes('\n')
	if err != nil {
		return err
	}
	ss, err := dcrypt.SharedSecretFromRecipient(identity, &to[0], ssJson)
	if err != nil {
		return err
	}

	// read file
	fileJson, err := r.ReadBytes('\n')
	if err != nil {
		return err
	}
	msg := mcrypt.Message{}
	err = json.Unmarshal(fileJson, &msg)
	if err != nil {
		return err
	}
	// decrypt payload
	payloadJson, err := ss.Decrypt(&msg)
	if err != nil {
		return err
	}
	// obtain payload structure
	p, err := dcrypt.NewPayloadFromJson(payloadJson, true)
	if err != nil {
		return err
	}

	// determine out file
	if outFilename == "" {
		_, err := os.Stat(p.Basename)
		if err == nil {
			return fmt.Errorf("target file already exists")
		}
		outFilename = p.Basename
	}

	err = ioutil.WriteFile(outFilename, p.Payload, 0600)
	if err != nil {
		return err
	}
	fmt.Printf("wrote file %v, remote suggestion was %v\n", outFilename,
		p.Basename)

	return nil
}
