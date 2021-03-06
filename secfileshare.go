package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"runtime"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/marcopeereboom/mcrypt"
	"github.com/marcopeereboom/secfileshare/dcrypt"
	"github.com/marcopeereboom/secfileshare/tunnel"
)

var (
	dir         string
	inFilename  string
	outFilename string
	upload      string
	mode        string
	description string
	identity    *mcrypt.Identity
)

func usage() {
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nCommon usage examples\n\n"+
		"== file to file ==\n"+
		"encrypt:\n"+
		"\tsecfileshare -in filename -out sharefilename -mode encrypt publickey\n"+
		"If -out is omitted the system will append .sfs to the -in filename\n\n"+
		"decrypt:\n"+
		"\tsecfileshare -in sharefilename -out decryptedblob -mode decrypt\n"+
		"If -out is omitted the system will use the remote filename hint\n\n"+
		"== file to server ==\n\n"+
		"\tsecfileshare -in filename -out https://a.b.c:12345 publickey\n\n"+
		"== server to file ==\n\n"+
		"\tsecfileshare -out decryptedblob -in https://a.b.c:12345/887123051\n"+
		"If -out is omitted the system will use the remote filename hint\n\n")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	help := false
	whoami := false

	flag.StringVar(&description, "desc", "", "description that will be"+
		"added to encrypted blob")
	flag.StringVar(&description, "d", "", "shorthand for -d")
	flag.StringVar(&inFilename, "in", "", "filename that will be "+
		"encrypted/decrypted")
	flag.StringVar(&outFilename, "out", "", "filename that will be "+
		"written out, when empty the system will guess based on the "+
		"mode of operation")
	flag.StringVar(&mode, "mode", "", "must be encrypt or decrypt, "+
		"only used in file to file mode")
	flag.BoolVar(&help, "h", false, "help")
	flag.BoolVar(&whoami, "whoami", false, "print identity information")
	flag.BoolVar(&whoami, "w", false, "shorthand for -whoami")
	flag.Parse()

	if help {
		usage()
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
	// secfileshare <url> [url...]
	if inFilename == "" && outFilename == "" {
		if len(flag.Args()) == 0 {
			// nothing to do, show usage
			usage()
			os.Exit(1)
		}

		// consider this "download many urls"
		for _, url := range flag.Args() {
			err := decodeFile(url)
			if err != nil {
				return err
			}
		}
		return nil
	}

	// detect URLs
	var outUrl, inUrl bool
	urlOut, err := url.Parse(outFilename)
	if err == nil {
		if urlOut.Scheme == "https" || urlOut.Scheme == "http" {
			// uploading
			outUrl = true
		}
	}
	urlIn, err := url.Parse(inFilename)
	if err == nil {
		if urlIn.Scheme == "https" || urlOut.Scheme == "http" {
			// downloading
			inUrl = true
		}
	}

	switch {
	case outUrl == false && inUrl == false:
		// file to file, require mode
		switch mode {
		case "encrypt":
			pk, err := parsePublicKeys()
			if err != nil {
				return err
			}
			if outFilename == "" {
				outFilename = inFilename + ".sfs"
			}
			_, err = os.Stat(outFilename)
			if err == nil {
				return fmt.Errorf("target file already exists")
			}
			return encodeFile(pk)

		case "decrypt":
			return decodeFile("")
		default:
			return fmt.Errorf("mode not set")
		}

	case outUrl == true && inUrl == false:
		// upload
		upload = urlOut.Host
		pk, err := parsePublicKeys()
		if err != nil {
			return err
		}
		return encodeFile(pk)

	case outUrl == false && inUrl == true:
		// download
		if len(flag.Args()) != 0 {
			return fmt.Errorf("must not provide additional " +
				"parameters")
		}
		url := inFilename
		inFilename = ""
		return decodeFile(url)

	default:
		return fmt.Errorf("only -in or -out may contain a URL")
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
		return fmt.Errorf("could not obtain user: %v", err)
	}
	dir = usr.HomeDir + homeDir
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return fmt.Errorf("could not create dir %v: %v", dir, err)
	}

	// test to see if we have an identity
	if identityExists() == false {
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("could not obtain hostname: %v", err)
		}

		identity, err = mcrypt.NewIdentity(usr.Name,
			usr.Username+"@"+host)
		if err != nil {
			return fmt.Errorf("could not create identity: %v", err)
		}

		err = identitySave()
		if err != nil {
			return fmt.Errorf("could not save identity: %v", err)
		}

		fmt.Printf("inital run, creating identity in %v\n",
			dir+identityFilename)
		printIdentity()
		os.Exit(0)
	}

	err = identityOpen()
	if err != nil {
		return fmt.Errorf("could not open identity: %v", err)
	}

	return nil
}

func parsePublicKeys() ([]mcrypt.PublicIdentity, error) {
	rv := make([]mcrypt.PublicIdentity, 0, len(flag.Args()))

	if len(flag.Args()) == 0 {
		return nil, fmt.Errorf("must provide public key(s)")
	}

	for i, v := range flag.Args() {
		v = strings.ToLower(v)
		v = strings.TrimPrefix(v, "0x")
		pk, err := hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("could not decode public "+
				"key number %v: %v", i+1, err)
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

func uploadFile(j1, j2 []byte) error {
	host, port, err := net.SplitHostPort(upload)
	if err != nil {
		return fmt.Errorf("invalid hostname %v: %v", upload, err)
	}

	client, err := tunnel.NewClient(host, port)
	if err != nil {
		return fmt.Errorf("could not create tunnel: %v", err)
	}

	cerr := make(chan error)
	go func() {
		var replyErr error
		defer func() {
			cerr <- replyErr
		}()

		// read reply
		response := tunnel.Response{}
		err := client.Conn.ReadJSON(&response)
		if err != nil {
			replyErr = fmt.Errorf("could not read remote "+
				"response: %v", err)
			return
		}
		if response.Error != "" {
			replyErr = fmt.Errorf("Remote error: %v",
				response.Error)
			return
		}

		// verify digest
		h := sha1.New()
		fmt.Fprintf(h, "%s\n%s\n", j1, j2)
		if response.Digest != fmt.Sprintf("%02x", h.Sum(nil)) {
			replyErr = fmt.Errorf("Remote digest failure")
			return
		}

		fmt.Printf("%v\n", response.Url)
		client.Conn.Close()
	}()

	err = client.Conn.WriteMessage(websocket.BinaryMessage, j1)
	if err != nil {
		return fmt.Errorf("could not write shared secret blob: %v",
			err)
	}

	err = client.Conn.WriteMessage(websocket.BinaryMessage, j2)
	if err != nil {
		return fmt.Errorf("could not write encrypted blob: %v", err)
	}

	return <-cerr
}

func encodeFile(to []mcrypt.PublicIdentity) error {
	// read file and generate payload structure
	p, err := dcrypt.NewPayload(inFilename, description, true)
	if err != nil {
		return fmt.Errorf("could not create payload: %v", err)
	}

	// make json
	pj, err := p.Marshal()
	if err != nil {
		return fmt.Errorf("could not marshal payload: %v", err)
	}

	// encrypt payload with shared key
	ss, err := dcrypt.NewSharedSecret("", "")
	if err != nil {
		return fmt.Errorf("could not create shared secret: %v", err)
	}
	msg, err := ss.Encrypt(pj)
	if err != nil {
		return fmt.Errorf("could not encrypt payload: %v", err)
	}
	msgJson, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("could not marshal encrypted payload: %v",
			err)
	}

	// encrypt shared key to other parties
	ssJson, err := json.Marshal(ss)
	if err != nil {
		return fmt.Errorf("could not marshal shared secret: %v", err)
	}

	// encrypt shared secrets to everyone
	j, err := dcrypt.NewEncryptedRecipients(identity, to, ssJson)
	if err != nil {
		return fmt.Errorf("could not encrypt shared secret: %v", err)
	}

	// write out bits
	if upload == "" {
		_, err = os.Stat(outFilename)
		if err == nil {
			tmpFd, err := ioutil.TempFile(path.Dir(outFilename),
				outFilename+".")
			if err != nil {
				return fmt.Errorf("could not create "+
					"temporary file: %v", err)
			}
			tmpFd.Close()
			outFilename = tmpFd.Name()
		}
		f, err := os.OpenFile(outFilename,
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("could not create file %v: %v",
				outFilename, err)
		}
		defer f.Close()
		fmt.Fprintf(f, "%s\n%s\n", j, msgJson)
	} else {
		return uploadFile(j, msgJson)
	}

	return nil
}

func decodeFile(url string) error {
	var r *bufio.Reader
	if inFilename == "" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		response, err := client.Get(url)
		if err != nil {
			return err
		}
		if response.StatusCode != 200 {
			return fmt.Errorf("remote error: %v", response.Status)
		}
		defer response.Body.Close()
		r = bufio.NewReader(response.Body)
	} else {
		f, err := os.Open(inFilename)
		if err != nil {
			return fmt.Errorf("could not open %v: %v\n",
				inFilename, err)
		}
		defer f.Close()
		r = bufio.NewReader(f)
	}

	// read shared secrets
	ssJson, err := r.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("Invalid shared secrets blob: %v", err)
	}
	ss, err := dcrypt.SharedSecretFromRecipient(identity,
		&identity.PublicIdentity, ssJson)
	if err != nil {
		// err is useless here
		s := inFilename
		if s == "" {
			s = url
		}
		return fmt.Errorf("invalid or corrupt shared secrets blob: %v",
			inFilename)
	}

	// read file
	fileJson, err := r.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("Invalid shared file blob: %v", err)
	}
	msg := mcrypt.Message{}
	err = json.Unmarshal(fileJson, &msg)
	if err != nil {
		return fmt.Errorf("could not decode shared file blob: %v", err)
	}
	// decrypt payload
	payloadJson, err := ss.Decrypt(&msg)
	if err != nil {
		return fmt.Errorf("could not decrypt payload: %v", err)
	}
	// obtain payload structure
	p, err := dcrypt.NewPayloadFromJson(payloadJson, true)
	if err != nil {
		return fmt.Errorf("could not decode payload: %v", err)
	}

	// determine out file
	if outFilename == "" {
		outFilename = p.Basename
	}

	_, err = os.Stat(outFilename)
	if err == nil {
		tmpFd, err := ioutil.TempFile(path.Dir(outFilename),
			outFilename+".")
		if err != nil {
			return fmt.Errorf("could not create temporary file %v",
				err)
		}
		tmpFd.Close()
		outFilename = tmpFd.Name()
	}

	err = ioutil.WriteFile(outFilename, p.Payload, 0600)
	if err != nil {
		return fmt.Errorf("could not write to %v: %v",
			outFilename, err)
	}
	if outFilename != p.Basename {
		fmt.Printf("wrote file %v, remote suggestion was %v\n", outFilename,
			p.Basename)
	} else {
		fmt.Printf("wrote file %v\n", outFilename)
	}
	d := p.Description
	if d == "" {
		d = "N/A"
	}
	fmt.Printf("remote description: %v\n", d)

	outFilename = "" // reset for decode many URLs

	return nil
}
