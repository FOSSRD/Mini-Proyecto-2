package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// scanType is the type of scan to perform in nmap
type scanType int

// This is where we define all of the existing values of the scanType type
const (
	tcpSyn scanType = iota
	tcpConnect
	tcpAck
	tcpWindow
	tcpMaimon
	udpScan
	tcpNull
)

// String returns a the flag corresponding to the scan type
func (s scanType) String() string {
	return [...]string{
		"-sS",
		"-sT",
		"-sA",
		"-sW",
		"-sM",
		"-sU",
		"-sN",
	}[s]
}

type Format int

const (
	normal Format = iota
	xml
	script
	grepable
)

// String returns a the flag corresponding to the output format
func (o Format) String() string {
	return [...]string{
		"-oN",
		"-oX",
		"-oS",
		"-oG",
	}[o]
}

type model struct {
	// The control part for the usage of the menu
	cursor int
	// page 1
	hostnames  string
	eHostnames string
	ports      string
	ePorts     string
	fastmode   bool
	// page 2
	listScan      bool
	pingScan      bool
	traceroute    bool
	skipDiscovery bool
	// page 3
	scanTechnique scanType
	// page 4
	versionDetection bool
	versionIntensity int
	// page 5
	osDetection bool
	osScanLimit bool
	osScanGuess bool
	// page 6
	outputFormat        Format
	verbosityLevel      int
	debugLevel          int
	showReasonPortState bool
	openPortsOnly       bool
	resume              string // not completely sure about this one, maybe have it autodetect
	outputFile          string
	// general returning error
	err error
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
			// These keys should exit the program.
		case "ctrl+c", "q":
			return m, tea.Quit

		// The "up" and "k" keys move the cursor up
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		// The "down" and "j" keys move the cursor down
		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
			}

		// The "enter" key and the spacebar (a literal space) toggle
		// the selected state for the item that the cursor is pointing at.
		case "enter", " ":
			_, ok := m.selected[m.cursor]
			if ok {
				delete(m.selected, m.cursor)
			} else {
				m.selected[m.cursor] = struct{}{}
			}
		}
	}

	return m, nil
}

func (m model) View() string {
	if m.err != nil {
		return m.err.Error()
	}
	return "Hello, world!"
}

func initialModel() model {
	return model{
		cursor: 0,
		// page 1
		hostnames:  "",
		eHostnames: "",
		ports:      "",
		ePorts:     "",
		fastmode:   true,
		// page 2
		listScan:      false,
		pingScan:      false,
		traceroute:    false,
		skipDiscovery: false,
		// page 3
		scanTechnique: tcpSyn,
		// page 4
		versionDetection: true,
		versionIntensity: 3,
		// page 5
		osDetection: false,
		osScanLimit: false,
		osScanGuess: false,
		// page 6
		outputFormat:        normal,
		verbosityLevel:      0,
		debugLevel:          0,
		showReasonPortState: false,
		openPortsOnly:       false,
		resume:              "", // not completely sure about this one, maybe have it autodetect
		outputFile:          "",
		// general returning error
		err: nil,
	}
}

func main() {
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}

//Nmap 7.94 ( https://nmap.org )
//Usage: nmap [Scan Type(s)] [Options] {target specification}
//TARGET SPECIFICATION:
//Can pass hostnames, IP addresses, networks, etc.
//Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
//--exclude <host1[,host2][,host3],...>: Exclude hosts/networks
//HOST DISCOVERY:
//-sL: List Scan - simply list targets to scan
//-sn: Ping Scan - disable port scan
//-Pn: Treat all hosts as online -- skip host discovery
//--traceroute: Trace hop path to each host
//SCAN TECHNIQUES:
//-sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
//-sU: UDP Scan
//-sN/: TCP Null
//-sI <zombie host[:probeport]>: Idle scan
//PORT SPECIFICATION AND SCAN ORDER:
//-p <port ranges>: Only scan specified ports
//Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
//--exclude-ports <port ranges>: Exclude the specified ports from scanning
//-F: Fast mode - Scan fewer ports than the default scan
//--top-ports <number>: Scan <number> most common ports
//SERVICE/VERSION DETECTION:
//-sV: Probe open ports to determine service/version info
//--version-intensity <level>: Set from 0 (light) to 9 (try all probes)
//OS DETECTION:
//-O: Enable OS detection
//--osscan-limit: Limit OS detection to promising targets
//--osscan-guess: Guess OS more aggressively
//OUTPUT:
//-oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
//and Grepable format, respectively, to the given filename.
//-v: Increase verbosity level (use -vv or more for greater effect)
//-d: Increase debugging level (use -dd or more for greater effect)
//--reason: Display the reason a port is in a particular state
//--open: Only show open (or possibly open) ports
//--resume <filename>: Resume an aborted scan
//MISC:
//-A: Enable OS detection, version detection, script scanning, and traceroute
//--datadir <dirname>: Specify custom Nmap data file location
//--privileged: Assume that the user is fully privileged
//--unprivileged: Assume the user lacks raw socket privileges

