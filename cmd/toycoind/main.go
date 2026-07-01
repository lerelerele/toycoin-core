package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"toycoin-core/internal/core"
)

type addNodes []string

func (a *addNodes) String() string     { return strings.Join(*a, ",") }
func (a *addNodes) Set(v string) error { *a = append(*a, v); return nil }

func main() {
	var datadir string
	var rpcListen string
	var rpcPort int
	var peers addNodes
	var toynet128 bool
	var authorityPubKey string
	flag.BoolVar(&toynet128, "toynet128", true, "run Toynet128 educational network")
	flag.StringVar(&datadir, "datadir", "", "data directory")
	flag.StringVar(&rpcListen, "rpclisten", "127.0.0.1", "RPC listen address; use 0.0.0.0 for seed nodes")
	flag.IntVar(&rpcPort, "rpcport", core.DefaultRPCPort, "RPC port")
	flag.Var(&peers, "addnode", "peer RPC URL or host:port; repeatable")
	flag.StringVar(&authorityPubKey, "authoritypubkey", "", "authority public key (toy128k1f hex) whose signed checkpoints this node trusts")
	var externalAddr string
	flag.StringVar(&externalAddr, "externaladdr", "", "reachable RPC URL to advertise for inventory gossip (e.g. http://seed:28443); empty = relay by pushing full data")
	flag.Parse()
	_ = toynet128

	n, err := core.LoadNode(datadir, peers)
	if err != nil {
		log.Fatal(err)
	}
	if authorityPubKey != "" {
		if _, err := core.ParsePublicKeyHex(authorityPubKey); err != nil {
			log.Fatalf("invalid -authoritypubkey: %v", err)
		}
		n.AuthorityPubKey = authorityPubKey
	}
	n.SelfURL = externalAddr
	stop := make(chan struct{})
	go n.SyncLoop(stop)

	addr := fmt.Sprintf("%s:%d", rpcListen, rpcPort)
	mux := http.NewServeMux()
	mux.HandleFunc("/", n.RPCHandler)
	mux.HandleFunc("/rpc", n.RPCHandler)
	mux.HandleFunc("/explorer", n.RPCHandler)

	log.Printf("[TOYCOIND] Toycoin Core v%s network=%s datadir=%s", core.Version, core.NetworkName, n.DataDir)
	log.Printf("[TOYCOIND] auth=cookie file=%s (regenerated each startup)", filepath.Join(n.DataDir, core.CookieFile))
	log.Printf("[TOYCOIND] dumpprivkey restricted to loopback connections")
	log.Printf("[TOYCOIND] curve=toy128k1f pow=SHA256d rpc=http://%s/rpc", addr)
	if n.AuthorityPubKey != "" {
		log.Printf("[TOYCOIND] authority checkpoints enabled; trusting pubkey=%s", n.AuthorityPubKey)
	}
	if n.SelfURL != "" {
		log.Printf("[NET] gossip: advertising %s (inv/getdata inventory relay)", n.SelfURL)
	} else {
		log.Printf("[NET] gossip: no -externaladdr; relaying by pushing full blocks/txs")
	}
	if len(n.Peers) > 0 {
		log.Printf("[NET] peers=%v", n.Peers)
	}
	log.Fatal(http.ListenAndServe(addr, mux))
}
