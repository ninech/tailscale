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

	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
	operatorutils "tailscale.com/k8s-operator"
	"tailscale.com/util/dnsname"
)

var (
	// domain is the DNS domain that this nameserver has registered a handler for.
	domain = flag.String("domain", "ts.net", "the DNS domain to serve records for")
)

const (
	// addr is the the address that the UDP and TCP listeners will listen on.
	addr = ":1053"

	// The following constants are specific to the nameserver configuration
	// provided by a mounted Kubernetes Configmap. The Configmap mounted at
	// /config is the only supported way for configuring this nameserver.
	defaultDNSConfigDir    = "/config"
	kubeletMountedConfigLn = "..data"
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
	// overridden in tests.
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

	// Ensure that we watch the kube Configmap mounted at /config for
	// nameserver configuration updates and send events when updates happen.
	c := ensureWatcherForKubeConfigMap(ctx)

	ns := &nameserver{
		configReader:  configMapConfigReader,
		configWatcher: c,
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
			w.WriteMsg(m)
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
			if ips == nil || len(ips) == 0 {
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
	if dnsCfgBytes == nil || len(dnsCfgBytes) < 1 {
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
		s.Shutdown()
	}()
	log.Printf("listening for %s queries on %s", net, addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("error running %s server: %v", net, err)
	}
}

// ensureWatcherForKubeConfigMap sets up a new file watcher for the ConfigMap
// that's expected to be mounted at /config. Returns a channel that receives an
// event every time the contents get updated.
func ensureWatcherForKubeConfigMap(ctx context.Context) chan string {
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
		defer watcher.Close()
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

// configMapConfigReader reads the desired nameserver configuration from a
// records.json file in a ConfigMap mounted at /config.
var configMapConfigReader configReaderFunc = func() ([]byte, error) {
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
