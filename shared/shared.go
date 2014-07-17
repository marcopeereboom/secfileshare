package main

import (
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/marcopeereboom/secfileshare/dcrypt"
	"github.com/marcopeereboom/secfileshare/tunnel"

	"os"
	"os/user"
	"runtime"
)

// Generate a random filename.
func newRandomFileName(tmpDir string) (string, error) {
	tmpFd, err := ioutil.TempFile(tmpDir, "")
	if err != nil {
		return "", err
	}
	filename := path.Base(tmpFd.Name())
	tmpFd.Close()
	return filename, nil

}

func httpCallback(w http.ResponseWriter, r *http.Request) {
	if r.RequestURI == "/" {
		fmt.Fprintf(w, "shared server\n")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, dropDirname+"/"+r.RequestURI)
}

func wsCallback(s *tunnel.Session) {
	//defer s.Conn.Close()
	rv := tunnel.Response{}
	defer func() {
		s.Conn.WriteJSON(rv)
		s.Conn.Close()
	}()

	_, j1, err := s.Conn.ReadMessage()
	if err != nil {
		rv.Error = fmt.Sprintf("error reading part 1")
		return
	}

	// make sure we can unmarshal j1
	msg := dcrypt.Recipients{}
	err = json.Unmarshal(j1, &msg)
	if err != nil {
		rv.Error = fmt.Sprintf("invalid format on j1: %v", err)
		return
	}

	_, j2, err := s.Conn.ReadMessage()
	if err != nil {
		rv.Error = fmt.Sprintf("error reading part 2")
		return
	}

	// store localy
	outFilename, err := newRandomFileName(dropDirname)
	if err != nil {
		rv.Error = fmt.Sprintf("newRandomFileName %v\n", err)
		return
	}
	f, err := os.OpenFile(dropDirname+"/"+outFilename,
		os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		rv.Error = fmt.Sprintf("OpenFile %v\n", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\n%s\n", j1, j2)

	// calculate digest
	h := sha1.New()
	fmt.Fprintf(h, "%s\n%s\n", j1, j2)
	rv.Digest = fmt.Sprintf("%02x", h.Sum(nil))
	rv.Url = fmt.Sprintf("https://%v/%v", hostName, outFilename)
}

const (
	homeDir  = "/.shared"
	certName = "/server.crt"
	keyName  = "/server.key"
	dropName = "/drop"
)

var (
	dir          string
	dropDirname  string
	certFilename string
	keyFilename  string
	hostName     string
)

func _main() error {
	flag.StringVar(&hostName, "host", "", "override hostname detection")
	flag.StringVar(&hostName, "h", "", "shorthand for -host")
	flag.Parse()

	certs()

	// setup dropzone
	dropDirname = dir + dropName
	err := os.MkdirAll(dropDirname, 0700)
	if err != nil {
		return err
	}

	// guess hostname if not set
	fmt.Printf("hostName %v\n", hostName)

	if hostName == "" {
		hostName, err = os.Hostname()
		if err != nil {
			return err
		}
		hostName += ":12345"
	}

	// start listening
	listeners := []string{hostName}
	_, err = tunnel.NewServer(listeners,
		certFilename,
		keyFilename,
		wsCallback,
		httpCallback)
	if err != nil {
		return fmt.Errorf("%v: %v", err, listeners)
	}

	fmt.Printf("Listening on %v\n", listeners)
	c := make(chan bool)
	<-c

	return nil
}

func certs() error {
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

	certFilename = dir + certName
	keyFilename = dir + keyName

	_, crt := os.Stat(certFilename)
	_, key := os.Stat(keyFilename)
	if crt == nil && key == nil {
		return nil
	}

	err = GenerateCert(certFilename, keyFilename)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
