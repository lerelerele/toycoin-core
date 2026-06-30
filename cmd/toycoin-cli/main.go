package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"toycoin-core/internal/core"
)

func main() {
	rpcURL := flag.String("rpc", fmt.Sprintf("http://127.0.0.1:%d/rpc", core.DefaultRPCPort), "RPC endpoint")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}
	method, params, err := translate(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	result, err := call(*rpcURL, method, params)
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

func usage() {
	fmt.Println(`Toycoin CLI v0.1.2

Examples:
  toycoin-cli getblockchaininfo
  toycoin-cli createwallet alumno
  toycoin-cli getnewaddress
  toycoin-cli generatetoaddress 1 tn1...
  toycoin-cli getbalance
  toycoin-cli sendtoaddress tn1... 10
  toycoin-cli listunspent
  toycoin-cli security walletreport
  toycoin-cli curveinfo`)
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
	case "getblockchaininfo", "getnetworkinfo", "getpeerinfo", "getnewaddress", "getbalance", "listunspent", "getrawmempool", "getblockcount", "getbestblockhash", "curveinfo":
		return cmd, []interface{}{}, nil
	default:
		return "", nil, fmt.Errorf("unknown command %q", args[0])
	}
}

func call(url, method string, params []interface{}) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]interface{}{"method": method, "params": params})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("bad response: %w: %s", err, string(raw))
	}
	if r.Error != "" {
		return nil, fmt.Errorf(r.Error)
	}
	return r.Result, nil
}
