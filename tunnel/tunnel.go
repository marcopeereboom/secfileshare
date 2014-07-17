package tunnel

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/gorilla/websocket"
)

const (
	rpcTimeoutSeconds = 10
)

// hack to share between server and client
type Response struct {
	Error  string `json:"error"`
	Url    string `json:"url"`
	Digest string `json:"digest"`
}

type Session struct {
	Conn   *websocket.Conn // websocket
	server bool            // indicate client or server
}

type Client struct {
	Session
}

type Server struct {
	listeners []net.Listener
}

func NewServer(listenAddrs []string, cert, key string,
	wsCallback func(*Session),
	httpCallback func(http.ResponseWriter, *http.Request)) (*Server, error) {
	keypair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	tlsConfig := tls.Config{
		Certificates:       []tls.Certificate{keypair},
		InsecureSkipVerify: true,
	}
	ipv4ListenAddrs, ipv6ListenAddrs, err := parseListeners(listenAddrs)
	listeners := make([]net.Listener, 0,
		len(ipv6ListenAddrs)+len(ipv4ListenAddrs))
	for _, addr := range ipv4ListenAddrs {
		listener, err := tls.Listen("tcp4", addr, &tlsConfig)
		if err != nil {
			continue
		}
		listeners = append(listeners, listener)
	}

	for _, addr := range ipv6ListenAddrs {
		listener, err := tls.Listen("tcp6", addr, &tlsConfig)
		if err != nil {
			continue
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 0 {
		return nil, fmt.Errorf("no valid listen address")
	}
	s := Server{
		listeners: listeners,
	}

	serveMux := http.NewServeMux()
	httpServer := &http.Server{
		Handler:     serveMux,
		ReadTimeout: time.Second * rpcTimeoutSeconds,
	}
	serveMux.HandleFunc("/tubes", func(w http.ResponseWriter, r *http.Request) {
		var (
			err     error
			session *Session = &Session{server: true}
		)
		session.Conn, err = websocket.Upgrade(w, r, w.Header(), 4096, 4096)
		if err != nil {
			// XXX
			fmt.Printf("Cannot websocket upgrade client %s: %v",
				r.RemoteAddr, err)
			return
		}
		wsCallback(session)
	})

	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpCallback(w, r)
	})

	for _, listener := range s.listeners {
		go func(listener net.Listener) {
			err = httpServer.Serve(listener)
		}(listener)
	}

	return &s, nil
}

func NewClient(address, port string) (*Client, error) {
	var err error
	addr := net.JoinHostPort(address, port)
	url := "wss://" + addr + "/tubes"
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: rpcTimeoutSeconds * time.Second,
		TLSClientConfig:  tlsConfig,
	}

	c := Client{}
	c.Conn, _, err = dialer.Dial(url, nil)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// parseListeners splits the list of listen addresses passed in addrs into
// IPv4 and IPv6 slices and returns them.  This allows easy creation of the
// listeners on the correct interface "tcp4" and "tcp6".  It also properly
// detects addresses which apply to "all interfaces" and adds the address to
// both slices.
func parseListeners(addrs []string) ([]string, []string, error) {
	ipv4ListenAddrs := make([]string, 0, len(addrs)*2)
	ipv6ListenAddrs := make([]string, 0, len(addrs)*2)
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// Shouldn't happen due to already being normalized.
			return nil, nil, err
		}

		// Empty host or host of * on plan9 is both IPv4 and IPv6.
		if host == "" || (host == "*" && runtime.GOOS == "plan9") {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
			continue
		}

		// Parse the IP.
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, nil, fmt.Errorf("'%s' is not a valid IP "+
				"address", host)
		}

		// To4 returns nil when the IP is not an IPv4 address, so use
		// this determine the address type.
		if ip.To4() == nil {
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
		} else {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
		}
	}
	return ipv4ListenAddrs, ipv6ListenAddrs, nil
}
