// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// k8s-nameserver is a simple nameserver implementation meant to be used with
// k8s-operator to allow to resolve magicDNS names associated with tailnet
// proxies in cluster.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	operatorutils "tailscale.com/k8s-operator"
	"tailscale.com/util/dnsname"
)

var (
	// domain is the DNS domain that this nameserver has registered a handler for.
	domain     = flag.String("domain", "ts.net", "the DNS domain to serve records for")
	updateMode = flag.String(
		"update-mode",
		mountAccessUpdateMode,
		fmt.Sprintf(
			"how to detect changes to the configMap which contains the DNS entries.\n"+
				"%q watches the mounted configMap for changes.\n"+
				"%q watches the configMap directly via the Kubernetes API.",
			mountAccessUpdateMode,
			directAccessUpdateMode,
		),
	)
)

const (
	// addr is the the address that the UDP and TCP listeners will listen on.
	addr = ":1053"

	// The following constants are specific to the nameserver configuration
	// provided by a mounted Kubernetes Configmap. The Configmap mounted at
	// /config is the only supported way for configuring this nameserver.
	defaultDNSConfigDir    = "/config"
	kubeletMountedConfigLn = "..data"

	// configMapName is the name of the configMap which needs to be watched
	// for changes when using the non-mount update mode.
	configMapName = "dnsrecords"
	// configMapKey is the configMap key which contains the DNS data
	configMapKey = "records.json"

	// the update modes define how changes to the configMap are detected.
	// Either by watching the mounted file (might be slower due to the time
	// needed for syncing) or by watching the configMap directly (needs
	// more permissions for the service account the k8s-namesever runs
	// with).
	directAccessUpdateMode = "direct-access"
	mountAccessUpdateMode  = "mount"

	// configMapDefaultNamespace sets the default namespace for reading the
	// configMap if the env variable POD_NAMESPACE is not set. Otherwise
	// the content of the POD_NAMESPACE env variable determines where to
	// read the configMap from. This only matters when using direct access
	// mode for updates.
	configMapDefaultNamespace = "tailscale"
)

// nameserver is a simple nameserver that responds to DNS queries for A records
// for the names of the given domain over UDP or TCP. It serves DNS responses from
// in-memory IPv4 host records. It is intended to be deployed on Kubernetes with
// a ConfigMap mounted at /config that should contain the host records. It
// dynamically reconfigures its in-memory mappings as the contents of the
// mounted ConfigMap changes.
type nameserver struct {
	// configReader returns the latest desired configuration (host records)
	// for the nameserver. By default it gets set to a reader that reads
	// from a Kubernetes ConfigMap mounted at /config, but this can be
	// overridden.
	configReader configReaderFunc
	// configWatcher is a watcher that returns an event when the desired
	// configuration has changed and the nameserver should update the
	// in-memory records.
	configWatcher <-chan string

	mu sync.Mutex // protects following
	// ip4 are the in-memory hostname -> IP4 mappings that the nameserver
	// uses to respond to A record queries.
	ip4 map[dnsname.FQDN][]net.IP
}

func main() {
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())

	if !validUpdateMode(*updateMode) {
		log.Fatalf("non valid update mode: %q", *updateMode)
	}

	reader, watcher, err := configMapReaderAndWatcher(ctx, *updateMode)
	if err != nil {
		log.Fatalf("can not setup configMap reader: %v", err)
	}
	ns := &nameserver{
		configReader:  reader,
		configWatcher: watcher,
	}

	// Ensure that in-memory records get set up to date now and will get
	// reset when the configuration changes.
	ns.runRecordsReconciler(ctx)

	// Register a DNS server handle for names of the domain. Not having a
	// handle registered for any other domain names is how we enforce that
	// this nameserver can only be used for the given domain - querying any
	// other domain names returns Rcode Refused.
	dns.HandleFunc(*domain, ns.handleFunc())

	// Listen for DNS queries over UDP and TCP.
	udpSig := make(chan os.Signal)
	tcpSig := make(chan os.Signal)
	go listenAndServe("udp", addr, udpSig)
	go listenAndServe("tcp", addr, tcpSig)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("OS signal (%s) received, shutting down", s)
	cancel()    // exit the records reconciler and configmap watcher goroutines
	udpSig <- s // stop the UDP listener
	tcpSig <- s // stop the TCP listener
}

// handleFunc is a DNS query handler that can respond to A record queries from
// the nameserver's in-memory records.
// - If an A record query is received and the
// nameserver's in-memory records contain records for the queried domain name,
// return a success response.
// - If an A record query is received, but the
// nameserver's in-memory records do not contain records for the queried domain name,
// return NXDOMAIN.
// - If an A record query is received, but the queried domain name is not valid, return Format Error.
// - If a query is received for any other record type than A, return Not Implemented.
func (n *nameserver) handleFunc() func(w dns.ResponseWriter, r *dns.Msg) {
	h := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		defer func() {
			_ = w.WriteMsg(m)
		}()
		if len(r.Question) < 1 {
			log.Print("[unexpected] nameserver received a request with no questions")
			m = r.SetRcodeFormatError(r)
			return
		}
		// TODO (irbekrm): maybe set message compression
		switch r.Question[0].Qtype {
		case dns.TypeA:
			q := r.Question[0].Name
			fqdn, err := dnsname.ToFQDN(q)
			if err != nil {
				m = r.SetRcodeFormatError(r)
				return
			}
			// The only supported use of this nameserver is as a
			// single source of truth for MagicDNS names by
			// non-tailnet Kubernetes workloads.
			m.Authoritative = true
			m.RecursionAvailable = false

			ips := n.lookupIP4(fqdn)
			if len(ips) == 0 {
				// As we are the authoritative nameserver for MagicDNS
				// names, if we do not have a record for this MagicDNS
				// name, it does not exist.
				m = m.SetRcode(r, dns.RcodeNameError)
				return
			}
			// TODO (irbekrm): TTL is currently set to 0, meaning
			// that cluster workloads will not cache the DNS
			// records. Revisit this in future when we understand
			// the usage patterns better- is it putting too much
			// load on kube DNS server or is this fine?
			for _, ip := range ips {
				rr := &dns.A{Hdr: dns.RR_Header{Name: q, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: ip}
				m.SetRcode(r, dns.RcodeSuccess)
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeAAAA:
			// TODO (irbekrm): add IPv6 support.
			// The nameserver currently does not support IPv6
			// (records are not being created for IPv6 Pod addresses).
			// However, we can expect that some callers will
			// nevertheless send AAAA queries.
			// We have to return NOERROR if a query is received for
			// an AAAA record for a DNS name that we have an A
			// record for- else the caller might not follow with an
			// A record query.
			// https://github.com/tailscale/tailscale/issues/12321
			// https://datatracker.ietf.org/doc/html/rfc4074
			q := r.Question[0].Name
			fqdn, err := dnsname.ToFQDN(q)
			if err != nil {
				m = r.SetRcodeFormatError(r)
				return
			}
			// The only supported use of this nameserver is as a
			// single source of truth for MagicDNS names by
			// non-tailnet Kubernetes workloads.
			m.Authoritative = true
			ips := n.lookupIP4(fqdn)
			if len(ips) == 0 {
				// As we are the authoritative nameserver for MagicDNS
				// names, if we do not have a record for this MagicDNS
				// name, it does not exist.
				m = m.SetRcode(r, dns.RcodeNameError)
				return
			}
			m.SetRcode(r, dns.RcodeSuccess)
		default:
			log.Printf("[unexpected] nameserver received a query for an unsupported record type: %s", r.Question[0].String())
			m.SetRcode(r, dns.RcodeNotImplemented)
		}
	}
	return h
}

// runRecordsReconciler ensures that nameserver's in-memory records are
// reset when the provided configuration changes.
func (n *nameserver) runRecordsReconciler(ctx context.Context) {
	log.Print("updating nameserver's records from the provided configuration...")
	if err := n.resetRecords(); err != nil { // ensure records are up to date before the nameserver starts
		log.Fatalf("error setting nameserver's records: %v", err)
	}
	log.Print("nameserver's records were updated")
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Printf("context cancelled, exiting records reconciler")
				return
			case <-n.configWatcher:
				log.Print("configuration update detected, resetting records")
				if err := n.resetRecords(); err != nil {
					// TODO (irbekrm): this runs in a
					// container that will be thrown away,
					// so this should be ok. But maybe still
					// need to ensure that the DNS server
					// terminates connections more
					// gracefully.
					log.Fatalf("error resetting records: %v", err)
				}
				log.Print("nameserver records were reset")
			}
		}
	}()
}

// resetRecords sets the in-memory DNS records of this nameserver from the
// provided configuration. It does not check for the diff, so the caller is
// expected to ensure that this is only called when reset is needed.
func (n *nameserver) resetRecords() error {
	dnsCfgBytes, err := n.configReader()
	if err != nil {
		log.Printf("error reading nameserver's configuration: %v", err)
		return err
	}
	if len(dnsCfgBytes) < 1 {
		log.Print("nameserver's configuration is empty, any in-memory records will be unset")
		n.mu.Lock()
		n.ip4 = make(map[dnsname.FQDN][]net.IP)
		n.mu.Unlock()
		return nil
	}
	dnsCfg := &operatorutils.Records{}
	err = json.Unmarshal(dnsCfgBytes, dnsCfg)
	if err != nil {
		return fmt.Errorf("error unmarshalling nameserver configuration: %v\n", err)
	}

	if dnsCfg.Version != operatorutils.Alpha1Version {
		return fmt.Errorf("unsupported configuration version %s, supported versions are %s\n", dnsCfg.Version, operatorutils.Alpha1Version)
	}

	ip4 := make(map[dnsname.FQDN][]net.IP)
	defer func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.ip4 = ip4
	}()

	if len(dnsCfg.IP4) == 0 {
		log.Print("nameserver's configuration contains no records, any in-memory records will be unset")
		return nil
	}

	for fqdn, ips := range dnsCfg.IP4 {
		fqdn, err := dnsname.ToFQDN(fqdn)
		if err != nil {
			log.Printf("invalid nameserver's configuration: %s is not a valid FQDN: %v; skipping this record", fqdn, err)
			continue // one invalid hostname should not break the whole nameserver
		}
		for _, ipS := range ips {
			ip := net.ParseIP(ipS).To4()
			if ip == nil { // To4 returns nil if IP is not a IPv4 address
				log.Printf("invalid nameserver's configuration: %v does not appear to be an IPv4 address; skipping this record", ipS)
				continue // one invalid IP address should not break the whole nameserver
			}
			ip4[fqdn] = []net.IP{ip}
		}
	}
	return nil
}

// listenAndServe starts a DNS server for the provided network and address.
func listenAndServe(net, addr string, shutdown chan os.Signal) {
	s := &dns.Server{Addr: addr, Net: net}
	go func() {
		<-shutdown
		log.Printf("shutting down server for %s", net)
		_ = s.Shutdown()
	}()
	log.Printf("listening for %s queries on %s", net, addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("error running %s server: %v", net, err)
	}
}

func getClientset() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}
	return clientset, nil
}

func getConfigMapNamespace() string {
	namespace := configMapDefaultNamespace
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		namespace = ns
	}
	return namespace
}

func configMapReaderAndWatcher(ctx context.Context, updateMode string) (configReaderFunc, chan string, error) {
	switch updateMode {
	case mountAccessUpdateMode:
		return configMapMountedReader, watchMountedConfigMap(ctx), nil
	case directAccessUpdateMode:
		cs, err := getClientset()
		if err != nil {
			return nil, nil, err
		}
		watcherChannel, cacheReader, err := watchConfigMap(ctx, cs, configMapName, getConfigMapNamespace())
		if err != nil {
			return nil, nil, err
		}
		return configMapCacheReader(cacheReader), watcherChannel, nil
	default:
		return nil, nil, fmt.Errorf("no implementation for update mode %q", updateMode)
	}
}

// watchConfigMap watches the configMap identified by the given name and
// namespace. It emits a message in the returned channel whenever the configMap
// updated. It also returns a configMapLister which allows to access the cached objects
// retrieved by the API server.
func watchConfigMap(ctx context.Context, cs kubernetes.Interface, configMapName, configMapNamespace string) (chan string, listersv1.ConfigMapLister, error) {
	ch := make(chan string)

	fieldSelector := fields.OneTermEqualSelector("metadata.name", configMapName).String()
	factory := informers.NewSharedInformerFactoryWithOptions(
		cs,
		// we resync every hour to account for missed watches
		time.Hour,
		informers.WithNamespace(configMapNamespace),
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fieldSelector
		}),
	)
	cmFactory := factory.Core().V1().ConfigMaps()
	_, _ = cmFactory.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			ch <- fmt.Sprintf("ConfigMap %s added or synced", configMapName)
		},
		UpdateFunc: func(oldObj, newObj any) {
			ch <- fmt.Sprintf("ConfigMap %s updated", configMapName)
		},
	})
	factory.Start(ctx.Done())
	// Wait for cache sync
	log.Println("waiting for configMap cache to sync")
	if !cache.WaitForCacheSync(ctx.Done(), cmFactory.Informer().HasSynced) {
		return nil, nil, fmt.Errorf("configMap cache did not sync successful")
	}
	log.Println("configMap cache successfully synced")

	return ch, cmFactory.Lister(), nil
}

// watchMountedConfigMap sets up a new file watcher for the ConfigMap
// that's expected to be mounted at /config. Returns a channel that receives an
// event every time the contents get updated.
func watchMountedConfigMap(ctx context.Context) chan string {
	c := make(chan string)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("error creating a new watcher for the mounted ConfigMap: %v", err)
	}
	// kubelet mounts configmap to a Pod using a series of symlinks, one of
	// which is <mount-dir>/..data that Kubernetes recommends consumers to
	// use if they need to monitor changes
	// https://github.com/kubernetes/kubernetes/blob/v1.28.1/pkg/volume/util/atomic_writer.go#L39-L61
	toWatch := filepath.Join(defaultDNSConfigDir, kubeletMountedConfigLn)
	go func() {
		defer func() {
			_ = watcher.Close()
		}()
		log.Printf("starting file watch for %s", defaultDNSConfigDir)
		for {
			select {
			case <-ctx.Done():
				log.Print("context cancelled, exiting ConfigMap watcher")
				return
			case event, ok := <-watcher.Events:
				if !ok {
					log.Fatal("watcher finished; exiting")
				}
				if event.Name == toWatch {
					msg := fmt.Sprintf("ConfigMap update received: %s", event)
					log.Print(msg)
					c <- msg
				}
			case err, ok := <-watcher.Errors:
				if err != nil {
					// TODO (irbekrm): this runs in a
					// container that will be thrown away,
					// so this should be ok. But maybe still
					// need to ensure that the DNS server
					// terminates connections more
					// gracefully.
					log.Fatalf("[unexpected] error watching configuration: %v", err)
				}
				if !ok {
					// TODO (irbekrm): this runs in a
					// container that will be thrown away,
					// so this should be ok. But maybe still
					// need to ensure that the DNS server
					// terminates connections more
					// gracefully.
					log.Fatalf("[unexpected] errors watcher exited")
				}
			}
		}
	}()
	if err = watcher.Add(defaultDNSConfigDir); err != nil {
		log.Fatalf("failed setting up a watcher for the mounted ConfigMap: %v", err)
	}
	return c
}

// configReaderFunc is a function that returns the desired nameserver configuration.
type configReaderFunc func() ([]byte, error)

func configMapCacheReader(lister listersv1.ConfigMapLister) configReaderFunc {
	return func() ([]byte, error) {
		cm, err := lister.ConfigMaps(getConfigMapNamespace()).Get(configMapName)
		if err != nil {
			return nil, fmt.Errorf("can not read configMap: %w", err)
		}
		if data, exists := cm.Data[configMapKey]; exists {
			return []byte(data), nil
		}
		// if the configMap is empty we need to return `nil` which will
		// be handled by the caller specifically
		return nil, nil
	}
}

// configMapMountedReader reads the desired nameserver configuration from a
// records.json file in a ConfigMap mounted at /config.
var configMapMountedReader configReaderFunc = func() ([]byte, error) {
	if contents, err := os.ReadFile(filepath.Join(defaultDNSConfigDir, operatorutils.DNSRecordsCMKey)); err == nil {
		return contents, nil
	} else if os.IsNotExist(err) {
		return nil, nil
	} else {
		return nil, err
	}
}

// lookupIP4 returns any IPv4 addresses for the given FQDN from nameserver's
// in-memory records.
func (n *nameserver) lookupIP4(fqdn dnsname.FQDN) []net.IP {
	if n.ip4 == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	f := n.ip4[fqdn]
	return f
}

func validUpdateMode(m string) bool {
	switch m {
	case directAccessUpdateMode, mountAccessUpdateMode:
		return true
	default:
		return false
	}
}
