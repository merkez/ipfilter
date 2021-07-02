package main

import (
	"flag"
	"fmt"

	"github.com/merkez/ipfilter/iptables"
)

var (
	iface       = flag.String("i", "eno1.4001", "interface to block traffic")
	ip          = flag.String("ip", "", "IP to be blocked")
	isTCP       = flag.Bool("tcp", true, "tcp traffic to be blocked")
	removeAllow = flag.Bool("removeAllow", false, "remove allow rule")
)

func main() {
	flag.Parse()
	// creating a client to use commands under IPTables
	client := iptables.IPTables{
		Sudo:     true,
		Debug:    true,
		ExecFunc: iptables.ShellExec,
	}
	// Assume that there is an interface which is called eth0
	if *removeAllow {
		fmt.Printf("Drop traffic rule removed on interface [ %s ] for ip [ %s ]\n", *iface, *ip)
		if err := client.RemoveDropTraffic(*iface, *ip, *isTCP); err != nil {
			panic(err)
		}
		return
	}
	if err := client.DropTraffic(*iface, *ip, *isTCP); err != nil {
		panic(err)
	}
	fmt.Printf("Drop traffic rule applied on interface [ %s ] for ip [ %s ]\n", *iface, *ip)

}
