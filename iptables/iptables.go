package iptables

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"

	"github.com/rs/zerolog/log"
)

type IPTables struct {
	Sudo bool

	// Flags to service
	Flags []string

	// enable Debug or not
	Debug bool

	// Implementation of ExecFunc.
	ExecFunc ExecFunc

	// Implementation of PipeFunc.
	PipeFunc PipeFunc
}

var (
	cmd = "iptables"
	//Name of the chaines
	inputC   = Chain("INPUT")
	forwardC = Chain("FORWARD")
	outputC  = Chain("OUTPUT")

	//name of the policy
	acceptP = Policy("ACCEPT")
	dropP   = Policy("DROP")
	rejectP = Policy("REJECT")
	returnP = Policy("RETURN")

	appendA = Action("-A")
	deleteA = Action("-D")       // delete action
	insertA = Action("--insert") // insert action

)

type Action string

type Chain string

type Policy string

type PipeFunc func(stdin io.Reader, cmd string, args ...string) ([]byte, error)

type ExecFunc func(cmd string, args ...string) ([]byte, error)

type Errori struct {
	Out []byte
	Err error
}

// iptables -A INPUT -i eth0 -s "$IP_TO_BE_BLOCKED" -j DROP
// iptables -A INPUT -i eth0 -p tcp -s "$IP_TO_BE_BLOCKED" -j DROP
func (ipTab *IPTables) DropTraffic(netInterface, ipAddress string, isTCP bool) error {

	cmds := []string{string(appendA), string(inputC), "-i", netInterface, "-s", ipAddress, "-j", string(dropP)}
	if isTCP {
		cmds = []string{string(appendA), string(inputC), "-i", netInterface, "-p", "tcp", "-s", ipAddress, "-j", string(dropP)}
	}
	_, err := ipTab.execute(cmds...)
	if err != nil {
		log.Error().Msgf("Error occurred while dropping traffic for ip [ %s ] on interface [ %s ]", ipAddress, netInterface)
		return err
	}
	log.Debug().Msgf("Traffic is dropped on interface [ %s ] for ip address [ %s ]", netInterface, ipAddress)
	return err
}

// iptables -D INPUT -i eth0 -s "$IP_TO_BE_BLOCKED" -j DROP
// iptables -D INPUT -i eth0 -p tcp -s "$IP_TO_BE_BLOCKED" -j DROP
func (ipTab *IPTables) RemoveDropTraffic(netInterface, ipAddress string, isTCP bool) error {

	cmds := []string{string(deleteA), string(inputC), "-i", netInterface, "-s", ipAddress, "-j", string(dropP)}
	if isTCP {
		cmds = []string{string(deleteA), string(inputC), "-i", netInterface, "-p", "tcp", "-s", ipAddress, "-j", string(dropP)}
	}
	_, err := ipTab.execute(cmds...)
	if err != nil {
		log.Error().Msgf("Error occurred while deleting traffic drop for ip [ %s ] on interface [ %s ]", ipAddress, netInterface)
		return err
	}
	log.Debug().Msgf("Rule for traffic drop on interface [ %s ] for ip address [ %s ] removed.", netInterface, ipAddress)
	return err
}

func (e Errori) Error() string {
	return fmt.Sprintf("%s: %s", e.Err, string(e.Out))
}

// exec executes an ExecFunc using 'iptables'.
func (ipTab *IPTables) execute(args ...string) ([]byte, error) {
	return ipTab.exec(cmd, args...)
}

// exec executes an ExecFunc using 'iptables'.
func (ipTab *IPTables) exec(cmd string, args ...string) ([]byte, error) {
	flags := append(ipTab.Flags, args...)

	// If needed, prefix Sudo.
	if ipTab.Sudo {
		flags = append([]string{cmd}, flags...)
		cmd = "sudo"
	}
	log.Debug().Msgf("exec %s %v", cmd, flags)
	out, err := ipTab.ExecFunc(cmd, flags...)
	if out != nil {
		out = bytes.TrimSpace(out)
		log.Debug().Msgf("exec: %q", string(out))
	}
	if err != nil {
		// Wrap errors in Error type for further introspection
		return nil, &Errori{
			Out: out,
			Err: err,
		}
	}
	return out, nil
}
func ShellExec(cmd string, args ...string) ([]byte, error) {
	return exec.Command(cmd, args...).CombinedOutput()
}
