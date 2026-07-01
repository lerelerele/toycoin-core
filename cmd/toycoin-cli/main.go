package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"toycoin-core/internal/core"
)

func main() {
	rpcURL := flag.String("rpc", fmt.Sprintf("http://127.0.0.1:%d/rpc", core.DefaultRPCPort), "RPC endpoint")
	datadir := flag.String("datadir", "", "data directory (to find the node .cookie for auth)")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}
	// Some authority tooling runs entirely locally (offline key handling) and
	// never touches the node RPC. Handle those before the RPC path.
	if handled, err := runLocal(args); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	method, params, err := translate(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	result, err := call(*rpcURL, method, params, *datadir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, result, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(result))
	}
}

// runLocal handles subcommands that must run offline with the authority key and
// never contact the node. Returns handled=true if it recognised the command.
func runLocal(args []string) (bool, error) {
	switch strings.ToLower(args[0]) {
	case "genauthoritykey":
		// Generate a fresh authority keypair. The private key must be kept
		// offline; only the public key is handed to the nodes via -authoritypubkey.
		d, err := core.RandomScalar()
		if err != nil {
			return true, err
		}
		P, err := core.PrivateToPublic(d)
		if err != nil {
			return true, err
		}
		pub, err := core.PublicKeyHex(P)
		if err != nil {
			return true, err
		}
		fmt.Println("authority private key (KEEP OFFLINE, do NOT put on a node):")
		fmt.Println("  " + core.PrivateKeyHex(d))
		fmt.Println("authority public key (give to nodes via -authoritypubkey):")
		fmt.Println("  " + pub)
		return true, nil
	case "signcheckpoint":
		// signcheckpoint <authority_priv_hex> <height> <blockhash>
		if len(args) != 4 {
			return true, fmt.Errorf("signcheckpoint requires <authority_priv_hex> <height> <blockhash>")
		}
		priv, err := core.ParsePrivateKeyHex(args[1])
		if err != nil {
			return true, err
		}
		height, err := strconv.Atoi(args[2])
		if err != nil {
			return true, err
		}
		cp, err := core.SignCheckpoint(priv, height, args[3])
		if err != nil {
			return true, err
		}
		out, _ := json.MarshalIndent(cp, "", "  ")
		fmt.Println(string(out))
		fmt.Println("\nSubmit it to a node with:")
		fmt.Printf("  toycoin-cli submitcheckpoint %d %s %s %s\n", cp.Height, cp.BlockHash, cp.PubKey, cp.Signature)
		return true, nil
	}
	return false, nil
}

// loadCookieAuth reads the node's .cookie file from the data directory and
// returns an Authorization header value. It returns "" if no cookie is found,
// so the CLI keeps working against a legacy node that disabled auth.
func loadCookieAuth(datadir string) string {
	if datadir == "" {
		datadir = core.DefaultDataDir()
	}
	cookiePath := filepath.Join(datadir, core.CookieFile)
	user, pass, err := core.ReadCookieFile(cookiePath)
	if err != nil {
		return ""
	}
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		return ""
	}
	req.SetBasicAuth(user, pass)
	return req.Header.Get("Authorization")
}

func usage() {
	fmt.Println("Toycoin CLI v" + core.Version + `

Examples:
  toycoin-cli getblockchaininfo
  toycoin-cli createwallet alumno
  toycoin-cli getnewaddress
  toycoin-cli generatetoaddress 1 tn1...
  toycoin-cli getbalance
  toycoin-cli sendtoaddress tn1... 10
  toycoin-cli listunspent
  toycoin-cli security walletreport
  toycoin-cli curveinfo

Authority / checkpoints:
  toycoin-cli genauthoritykey                       (offline: make an authority keypair)
  toycoin-cli signcheckpoint <priv> <height> <hash> (offline: sign a checkpoint)
  toycoin-cli submitcheckpoint <height> <hash> <pubkey> <sig>
  toycoin-cli getcheckpoint`)
}

func translate(args []string) (string, []interface{}, error) {
	cmd := strings.ToLower(args[0])
	switch cmd {
	case "security":
		if len(args) < 2 {
			return "", nil, fmt.Errorf("security subcommand required")
		}
		if strings.ToLower(args[1]) == "walletreport" {
			return "security.walletreport", []interface{}{}, nil
		}
		return "", nil, fmt.Errorf("unknown security subcommand")
	case "createwallet", "getblock", "validateaddress", "dumpprivkey":
		if len(args) != 2 {
			return "", nil, fmt.Errorf("%s requires 1 argument", cmd)
		}
		return cmd, []interface{}{args[1]}, nil
	case "getblockhash":
		if len(args) != 2 {
			return "", nil, fmt.Errorf("getblockhash requires height")
		}
		h, err := strconv.Atoi(args[1])
		if err != nil {
			return "", nil, err
		}
		return cmd, []interface{}{h}, nil
	case "generatetoaddress":
		if len(args) != 3 {
			return "", nil, fmt.Errorf("generatetoaddress requires count address")
		}
		c, err := strconv.Atoi(args[1])
		if err != nil {
			return "", nil, err
		}
		return cmd, []interface{}{c, args[2]}, nil
	case "sendtoaddress":
		if len(args) != 3 {
			return "", nil, fmt.Errorf("sendtoaddress requires address amount")
		}
		return cmd, []interface{}{args[1], args[2]}, nil
	case "submitcheckpoint":
		// submitcheckpoint <height> <blockhash> <pubkey> <signature>
		if len(args) != 5 {
			return "", nil, fmt.Errorf("submitcheckpoint requires <height> <blockhash> <pubkey> <signature>")
		}
		h, err := strconv.Atoi(args[1])
		if err != nil {
			return "", nil, err
		}
		cp := map[string]interface{}{"height": h, "block_hash": args[2], "pub_key": args[3], "signature": args[4]}
		return "submitcheckpoint", []interface{}{cp}, nil
	case "getblockchaininfo", "getnetworkinfo", "getpeerinfo", "getnewaddress", "getbalance", "listunspent", "getrawmempool", "getblockcount", "getbestblockhash", "curveinfo", "getcheckpoint":
		return cmd, []interface{}{}, nil
	default:
		return "", nil, fmt.Errorf("unknown command %q", args[0])
	}
}

func call(url, method string, params []interface{}, datadir string) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]interface{}{"method": method, "params": params})
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth := loadCookieAuth(datadir); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		hint := "the node requires cookie auth; make sure -datadir points at the node's data directory (contains .cookie)"
		return nil, fmt.Errorf("401 Unauthorized: %s", hint)
	}
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("bad response: %w: %s", err, string(raw))
	}
	if r.Error != "" {
		// Use %s so an error message containing % is not treated as a format verb.
		return nil, fmt.Errorf("%s", r.Error)
	}
	return r.Result, nil
}
