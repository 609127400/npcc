package common

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	GRPCDefaultMaxRecvMsgSize = 100 * 1024 * 1024
	GRPCDefaultMaxSendMsgSize = 100 * 1024 * 1024
)

var (
	// Default peer keepalive options
	DefaultKeepaliveOptions = KeepaliveOptions{
		ClientInterval:    time.Duration(1) * time.Minute,  // 1 min
		ClientTimeout:     time.Duration(20) * time.Second, // 20 sec - gRPC default
		ServerInterval:    time.Duration(2) * time.Hour,    // 2 hours - gRPC default
		ServerTimeout:     time.Duration(20) * time.Second, // 20 sec - gRPC default
		ServerMinInterval: time.Duration(1) * time.Minute,  // match ClientInterval
	}
	// strong TLS cipher suites
	DefaultTLSCipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
	// default connection timeout
	DefaultConnectionTimeout        = 5 * time.Second
	DefaultGRPCKeepaliveInterval    = 7200 * time.Second
	DefaultGRPCKeepaliveTimeout     = 3 * time.Second
	DefaultGRPCKeepaliveMinInterval = 60 * time.Second
)

var (
	ErrClientHandshakeNotImplemented = errors.New("client handshakes are not implemented with serverCreds")
	ErrServerHandshakeNotImplemented = errors.New("server handshakes are not implemented with clientCreds")
	ErrOverrideHostnameNotSupported  = errors.New("OverrideServerName is not supported")

	// alpnProtoStr are the specified application level protocols for gRPC.
	alpnProtoStr = []string{"h2"}
)

// NewServerTransportCredentials returns a new initialized
// grpc/credentials.TransportCredentials
func NewServerTransportCredentials(serverConfig *TLSConfig) credentials.TransportCredentials {
	// NOTE: unlike the default grpc/credentials implementation, we do not
	// clone the tls.Config which allows us to update it dynamically
	serverConfig.config.NextProtos = alpnProtoStr
	serverConfig.config.MinVersion = tls.VersionTLS12

	return &serverCreds{
		serverConfig: serverConfig,
	}
}

// serverCreds is an implementation of grpc/credentials.TransportCredentials.
type serverCreds struct {
	serverConfig *TLSConfig
	//logger       *flogging.FabricLogger
}

type TLSConfig struct {
	config *tls.Config
	lock   sync.RWMutex
}

func NewTLSConfig(config *tls.Config) *TLSConfig {
	return &TLSConfig{
		config: config,
	}
}

func (t *TLSConfig) Config() tls.Config {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if t.config != nil {
		return *t.config.Clone()
	}

	return tls.Config{}
}

func (t *TLSConfig) AddClientRootCA(cert *x509.Certificate) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.config.ClientCAs.AddCert(cert)
}

func (t *TLSConfig) SetClientCAs(certPool *x509.CertPool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.config.ClientCAs = certPool
}

// ClientHandShake is not implemented for `serverCreds`.
func (sc *serverCreds) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrClientHandshakeNotImplemented
}

// ServerHandshake does the authentication handshake for servers.
func (sc *serverCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	serverConfig := sc.serverConfig.Config()

	conn := tls.Server(rawConn, &serverConfig)
	start := time.Now()
	if err := conn.Handshake(); err != nil {
		fmt.Printf("Server TLS handshake failed in %s with error %s", time.Since(start), err)
		return nil, nil, err
	}
	fmt.Printf("Server TLS handshake completed in %s\n", time.Since(start))
	return conn, credentials.TLSInfo{State: conn.ConnectionState()}, nil
}

// Info provides the ProtocolInfo of this TransportCredentials.
func (sc *serverCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
	}
}

// Clone makes a copy of this TransportCredentials.
func (sc *serverCreds) Clone() credentials.TransportCredentials {
	config := sc.serverConfig.Config()
	serverConfig := NewTLSConfig(&config)
	return NewServerTransportCredentials(serverConfig)
}

// OverrideServerName overrides the server name used to verify the hostname
// on the returned certificates from the server.
func (sc *serverCreds) OverrideServerName(string) error {
	return ErrOverrideHostnameNotSupported
}

type DynamicClientCredentials struct {
	TLSConfig *tls.Config
}

func (dtc *DynamicClientCredentials) latestConfig() *tls.Config {
	return dtc.TLSConfig.Clone()
}

func (dtc *DynamicClientCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	creds := credentials.NewTLS(dtc.latestConfig())
	start := time.Now()
	conn, auth, err := creds.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		fmt.Printf("Client TLS handshake failed after %s with error: %s\n", time.Since(start), err)
	} else {
		fmt.Printf("Client TLS handshake completed in %s\n", time.Since(start))
	}
	return conn, auth, err
}

func (dtc *DynamicClientCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrServerHandshakeNotImplemented
}

func (dtc *DynamicClientCredentials) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(dtc.latestConfig()).Info()
}

func (dtc *DynamicClientCredentials) Clone() credentials.TransportCredentials {
	return credentials.NewTLS(dtc.latestConfig())
}

func (dtc *DynamicClientCredentials) OverrideServerName(name string) error {
	dtc.TLSConfig.ServerName = name
	return nil
}

type GRPCServerConfig struct {
	// ConnectionTimeout specifies the timeout for connection establishment
	// for all new connections
	ConnectionTimeout time.Duration
	// SecOpts defines the security parameters
	SecOpts SecureOptions
	// KaOpts defines the keepalive parameters
	KaOpts KeepaliveOptions
	// 两种拦截器，fabric中用于统计、计数
	// StreamInterceptors specifies a list of interceptors to apply to
	// streaming RPCs.  They are executed in order.
	//StreamInterceptors []grpc.StreamServerInterceptor
	// UnaryInterceptors specifies a list of interceptors to apply to unary
	// RPCs.  They are executed in order.
	//UnaryInterceptors []grpc.UnaryServerInterceptor
	// Logger specifies the logger the server will use
	//Logger *flogging.FabricLogger
	// HealthCheckEnabled enables the gRPC Health Checking Protocol for the server
	HealthCheckEnabled bool
	// ServerStatsHandler should be set if metrics on connections are to be reported.
	//ServerStatsHandler *ServerStatsHandler
	// Maximum message size the server can receive
	MaxRecvMsgSize int
	// Maximum message size the server can send
	MaxSendMsgSize int
}

// GRPCClientConfig defines the parameters for configuring a GRPCClient instance
type GRPCClientConfig struct {
	// SecOpts defines the security parameters
	SecOpts SecureOptions
	// KaOpts defines the keepalive parameters
	KaOpts KeepaliveOptions
	// DialTimeout controls how long the client can block when attempting to
	// establish a connection to a server
	DialTimeout time.Duration
	// AsyncConnect makes connection creation non blocking
	AsyncConnect bool
	// Maximum message size the client can receive
	MaxRecvMsgSize int
	// Maximum message size the client can send
	MaxSendMsgSize int
}

// Convert the GRPCClientConfig to the approriate set of grpc.DialOptions.
func (cc GRPCClientConfig) DialOptions() ([]grpc.DialOption, error) {
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                cc.KaOpts.ClientInterval,
		Timeout:             cc.KaOpts.ClientTimeout,
		PermitWithoutStream: true,
	}))

	// Unless asynchronous connect is set, make connection establishment blocking.
	if !cc.AsyncConnect {
		dialOpts = append(dialOpts,
			grpc.WithBlock(),
			grpc.FailOnNonTempDialError(true),
		)
	}
	// set send/recv message size to package defaults
	maxRecvMsgSize := GRPCDefaultMaxRecvMsgSize
	if cc.MaxRecvMsgSize != 0 {
		maxRecvMsgSize = cc.MaxRecvMsgSize
	}
	maxSendMsgSize := GRPCDefaultMaxSendMsgSize
	if cc.MaxSendMsgSize != 0 {
		maxSendMsgSize = cc.MaxSendMsgSize
	}
	dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(
		grpc.MaxCallRecvMsgSize(maxRecvMsgSize),
		grpc.MaxCallSendMsgSize(maxSendMsgSize),
	))

	tlsConfig, err := cc.SecOpts.TLSConfig()
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		transportCreds := &DynamicClientCredentials{TLSConfig: tlsConfig}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(transportCreds))
	} else {
		dialOpts = append(dialOpts, grpc.WithInsecure())
	}

	return dialOpts, nil
}

func (cc GRPCClientConfig) Dial(address string) (*grpc.ClientConn, error) {
	dialOpts, err := cc.DialOptions()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cc.DialTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, address, dialOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new connection")
	}
	return conn, nil
}

// SecureOptions defines the TLS security parameters for a GRPCServer or
// GRPCClient instance.
type SecureOptions struct {
	// VerifyCertificate, if not nil, is called after normal
	// certificate verification by either a TLS client or server.
	// If it returns a non-nil error, the handshake is aborted and that error results.
	VerifyCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	// PEM-encoded X509 public key to be used for TLS communication
	Certificate []byte
	// PEM-encoded private key to be used for TLS communication
	Key []byte
	// Set of PEM-encoded X509 certificate authorities used by clients to
	// verify server certificates
	ServerRootCAs [][]byte
	// Set of PEM-encoded X509 certificate authorities used by servers to
	// verify client certificates
	ClientRootCAs [][]byte
	// Whether or not to use TLS for communication
	UseTLS bool
	// Whether or not TLS client must present certificates for authentication
	RequireClientCert bool
	// CipherSuites is a list of supported cipher suites for TLS
	CipherSuites []uint16
	// TimeShift makes TLS handshakes time sampling shift to the past by a given duration
	TimeShift time.Duration
	// ServerNameOverride is used to verify the hostname on the returned certificates. It
	// is also included in the client's handshake to support virtual hosting
	// unless it is an Addr address.
	ServerNameOverride string
}

func (so SecureOptions) TLSConfig() (*tls.Config, error) {
	// if TLS is not enabled, return
	if !so.UseTLS {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		MinVersion:            tls.VersionTLS12,
		ServerName:            so.ServerNameOverride,
		VerifyPeerCertificate: so.VerifyCertificate,
	}
	if len(so.ServerRootCAs) > 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		for _, certBytes := range so.ServerRootCAs {
			if !tlsConfig.RootCAs.AppendCertsFromPEM(certBytes) {
				return nil, errors.New("error adding root certificate")
			}
		}
	}

	if so.RequireClientCert {
		cert, err := so.ClientCertificate()
		if err != nil {
			return nil, errors.WithMessage(err, "failed to load client certificate")
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	if so.TimeShift > 0 {
		tlsConfig.Time = func() time.Time {
			return time.Now().Add((-1) * so.TimeShift)
		}
	}

	return tlsConfig, nil
}

// ClientCertificate returns the client certificate that will be used
// for mutual TLS.
func (so SecureOptions) ClientCertificate() (tls.Certificate, error) {
	if so.Key == nil || so.Certificate == nil {
		return tls.Certificate{}, errors.New("both Key and Certificate are required when using mutual TLS")
	}
	cert, err := tls.X509KeyPair(so.Certificate, so.Key)
	if err != nil {
		return tls.Certificate{}, errors.WithMessage(err, "failed to create key pair")
	}
	return cert, nil
}

// KeepaliveOptions is used to set the gRPC keepalive settings for both
// clients and servers
type KeepaliveOptions struct {
	// ClientInterval is the duration after which if the client does not see
	// any activity from the server it pings the server to see if it is alive
	ClientInterval time.Duration
	// ClientTimeout is the duration the client waits for a response
	// from the server after sending a ping before closing the connection
	ClientTimeout time.Duration
	// ServerInterval is the duration after which if the server does not see
	// any activity from the client it pings the client to see if it is alive
	ServerInterval time.Duration
	// ServerTimeout is the duration the server waits for a response
	// from the client after sending a ping before closing the connection
	ServerTimeout time.Duration
	// ServerMinInterval is the minimum permitted time between client pings.
	// If clients send pings more frequently, the server will disconnect them
	ServerMinInterval time.Duration
}

// ServerKeepaliveOptions returns gRPC keepalive options for a server.
func (ka KeepaliveOptions) ServerKeepaliveOptions() []grpc.ServerOption {
	var serverOpts []grpc.ServerOption
	kap := keepalive.ServerParameters{
		Time:    ka.ServerInterval,
		Timeout: ka.ServerTimeout,
	}
	serverOpts = append(serverOpts, grpc.KeepaliveParams(kap))
	kep := keepalive.EnforcementPolicy{
		MinTime: ka.ServerMinInterval,
		// allow keepalive w/o rpc
		PermitWithoutStream: true,
	}
	serverOpts = append(serverOpts, grpc.KeepaliveEnforcementPolicy(kep))
	return serverOpts
}

// ClientKeepaliveOptions returns gRPC keepalive dial options for clients.
func (ka KeepaliveOptions) ClientKeepaliveOptions() []grpc.DialOption {
	var dialOpts []grpc.DialOption
	kap := keepalive.ClientParameters{
		Time:                ka.ClientInterval,
		Timeout:             ka.ClientTimeout,
		PermitWithoutStream: true,
	}
	dialOpts = append(dialOpts, grpc.WithKeepaliveParams(kap))
	return dialOpts
}

type GRPCServer struct {
	// Listen address for the server specified as hostname:port
	address string
	// Listener for handling network requests
	listener net.Listener
	// GRPC server
	server *grpc.Server
	// Certificate presented by the server for TLS communication
	// stored as an atomic reference
	serverCertificate atomic.Value
	// lock to protect concurrent access to append / remove
	lock *sync.Mutex
	// TLS configuration used by the grpc server
	tls *TLSConfig
	// Server for gRPC Health Check Protocol.
	healthServer *health.Server
}

func NewGRPCServer(address string, serverConfig *GRPCServerConfig) (*GRPCServer, error) {
	if address == "" {
		return nil, errors.New("missing address parameter")
	}
	// create our listener
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return NewGRPCServerFromListener(lis, serverConfig)
}

// NewGRPCServerFromListener creates a new implementation of a GRPCServer given
// an existing net.Listener instance using default keepalive
func NewGRPCServerFromListener(listener net.Listener, serverConfig *GRPCServerConfig) (*GRPCServer, error) {
	grpcServer := &GRPCServer{
		address:  listener.Addr().String(),
		listener: listener,
		lock:     &sync.Mutex{},
	}

	// set up our server options
	var serverOpts []grpc.ServerOption

	secureConfig := serverConfig.SecOpts
	if secureConfig.UseTLS {
		// both key and cert are required
		if secureConfig.Key != nil && secureConfig.Certificate != nil {
			// load server public and private keys
			cert, err := tls.X509KeyPair(secureConfig.Certificate, secureConfig.Key)
			if err != nil {
				return nil, err
			}

			grpcServer.serverCertificate.Store(cert)

			// set up our TLS config
			if len(secureConfig.CipherSuites) == 0 {
				secureConfig.CipherSuites = DefaultTLSCipherSuites
			}
			getCert := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert := grpcServer.serverCertificate.Load().(tls.Certificate)
				return &cert, nil
			}

			grpcServer.tls = NewTLSConfig(&tls.Config{
				VerifyPeerCertificate:  secureConfig.VerifyCertificate,
				GetCertificate:         getCert,
				SessionTicketsDisabled: true,
				CipherSuites:           secureConfig.CipherSuites,
			})

			if serverConfig.SecOpts.TimeShift > 0 {
				timeShift := serverConfig.SecOpts.TimeShift
				grpcServer.tls.config.Time = func() time.Time {
					return time.Now().Add((-1) * timeShift)
				}
			}
			grpcServer.tls.config.ClientAuth = tls.RequestClientCert
			// check if client authentication is required
			if secureConfig.RequireClientCert {
				// require TLS client auth
				grpcServer.tls.config.ClientAuth = tls.RequireAndVerifyClientCert
				// if we have client root CAs, create a certPool
				if len(secureConfig.ClientRootCAs) > 0 {
					grpcServer.tls.config.ClientCAs = x509.NewCertPool()
					for _, clientRootCA := range secureConfig.ClientRootCAs {
						err = grpcServer.appendClientRootCA(clientRootCA)
						if err != nil {
							return nil, err
						}
					}
				}
			}

			// create credentials and add to server options
			creds := NewServerTransportCredentials(grpcServer.tls)
			serverOpts = append(serverOpts, grpc.Creds(creds))
		} else {
			return nil, errors.New("serverConfig.SecOpts must contain both Key and Certificate when UseTLS is true")
		}
	}

	// set max send and recv msg sizes
	maxSendMsgSize := GRPCDefaultMaxSendMsgSize
	if serverConfig.MaxSendMsgSize != 0 {
		maxSendMsgSize = serverConfig.MaxSendMsgSize
	}
	maxRecvMsgSize := GRPCDefaultMaxRecvMsgSize
	if serverConfig.MaxRecvMsgSize != 0 {
		maxRecvMsgSize = serverConfig.MaxRecvMsgSize
	}
	serverOpts = append(serverOpts, grpc.MaxSendMsgSize(maxSendMsgSize))
	serverOpts = append(serverOpts, grpc.MaxRecvMsgSize(maxRecvMsgSize))
	// set the keepalive options
	serverOpts = append(serverOpts, serverConfig.KaOpts.ServerKeepaliveOptions()...)
	// set connection timeout
	if serverConfig.ConnectionTimeout <= 0 {
		serverConfig.ConnectionTimeout = DefaultConnectionTimeout
	}
	serverOpts = append(
		serverOpts,
		grpc.ConnectionTimeout(serverConfig.ConnectionTimeout))

	grpcServer.server = grpc.NewServer(serverOpts...)

	if serverConfig.HealthCheckEnabled {
		grpcServer.healthServer = health.NewServer()
		healthpb.RegisterHealthServer(grpcServer.server, grpcServer.healthServer)
	}

	return grpcServer, nil
}

// SetServerCertificate assigns the current TLS certificate to be the peer's server certificate
func (gServer *GRPCServer) SetServerCertificate(cert tls.Certificate) {
	gServer.serverCertificate.Store(cert)
}

// Address returns the listen address for this GRPCServer instance
func (gServer *GRPCServer) Address() string {
	return gServer.address
}

// Listener returns the net.Listener for the GRPCServer instance
func (gServer *GRPCServer) Listener() net.Listener {
	return gServer.listener
}

// Server returns the grpc.Server for the GRPCServer instance
func (gServer *GRPCServer) Server() *grpc.Server {
	return gServer.server
}

// ServerCertificate returns the tls.Certificate used by the grpc.Server
func (gServer *GRPCServer) ServerCertificate() tls.Certificate {
	return gServer.serverCertificate.Load().(tls.Certificate)
}

// TLSEnabled is a flag indicating whether or not TLS is enabled for the
// GRPCServer instance
func (gServer *GRPCServer) TLSEnabled() bool {
	return gServer.tls != nil
}

// MutualTLSRequired is a flag indicating whether or not client certificates
// are required for this GRPCServer instance
func (gServer *GRPCServer) MutualTLSRequired() bool {
	return gServer.TLSEnabled() &&
		gServer.tls.Config().ClientAuth == tls.RequireAndVerifyClientCert
}

// Start starts the underlying grpc.Server
func (gServer *GRPCServer) Start() error {
	// if health check is enabled, set the health status for all registered services
	if gServer.healthServer != nil {
		for name := range gServer.server.GetServiceInfo() {
			gServer.healthServer.SetServingStatus(
				name,
				healthpb.HealthCheckResponse_SERVING,
			)
		}

		gServer.healthServer.SetServingStatus(
			"",
			healthpb.HealthCheckResponse_SERVING,
		)
	}
	return gServer.server.Serve(gServer.listener)
}

// Stop stops the underlying grpc.Server
func (gServer *GRPCServer) Stop() {
	gServer.server.Stop()
}

// internal function to add a PEM-encoded clientRootCA
func (gServer *GRPCServer) appendClientRootCA(clientRoot []byte) error {
	certs, err := pemToX509Certs(clientRoot)
	if err != nil {
		return errors.WithMessage(err, "failed to append client root certificate(s)")
	}

	if len(certs) < 1 {
		return errors.New("no client root certificates found")
	}

	for _, cert := range certs {
		gServer.tls.AddClientRootCA(cert)
	}

	return nil
}

// parse PEM-encoded certs
func pemToX509Certs(pemCerts []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// it's possible that multiple certs are encoded
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// SetClientRootCAs sets the list of authorities used to verify client
// certificates based on a list of PEM-encoded X509 certificate authorities
func (gServer *GRPCServer) SetClientRootCAs(clientRoots [][]byte) error {
	gServer.lock.Lock()
	defer gServer.lock.Unlock()

	certPool := x509.NewCertPool()
	for _, clientRoot := range clientRoots {
		if !certPool.AppendCertsFromPEM(clientRoot) {
			return errors.New("failed to set client root certificate(s)")
		}
	}
	gServer.tls.SetClientCAs(certPool)
	return nil
}
