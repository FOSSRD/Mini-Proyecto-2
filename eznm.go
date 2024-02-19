package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	focusedStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("30"))
	blurredStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cursorStyle         = focusedStyle.Copy()
	noStyle             = lipgloss.NewStyle()
	helpStyle           = blurredStyle.Copy()
	//delete next line
	//cursorModeHelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	helpMenuColor = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	focusedSubmitButton = focusedStyle.Copy().Render("[ Submit ]")
	blurredSubmitButton = fmt.Sprintf("[ %s ]", blurredStyle.Render("Submit"))
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
	hostnames  textinput.Model
	eHostnames textinput.Model
	ports      textinput.Model
	ePorts     textinput.Model
	fastmode   bool
	// page 2  4
	listScan      bool
	pingScan      bool
	traceroute    bool
	skipDiscovery bool
	// page 3  8
	scanTechnique scanType
	// page 4  9
	versionDetection bool
	versionIntensity int
	// page 5  11
	osDetection bool
	osScanLimit bool
	osScanGuess bool
	// page 6  14
	outputFormat        Format
	verbosityLevel      int
	debugLevel          int
	showReasonPortState bool
	openPortsOnly       bool
	resume              textinput.Model // not completely sure about this one, maybe have it autodetect
	outputFile          textinput.Model
	// general returning error  21
	err error
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

}


func (m model) View() string {

}

func initialModel() model {
	var m model
	t := textinput.New()
	t.Cursor.Style = cursorStyle
	t.CharLimit = 64
	

	m.hostnames := t
	m.hostnames.Focus()
	m.hostnames.PromptStyle = focusedStyle
	m.hostnames.TextStyle = focusedStyle
	m.hostnames.Placeholder = "Hostnames to scan"

	m.eHostnames := t
	m.eHostnames.Placeholder = "Hostnames to exclude"

	m.ports := t
	m.ports.Placeholder = "Ports to scan"

	m.ePorts := t
	m.ePorts.Placeholder = "Ports to exclude"

	m.fastmode = true
	m.listScan = false
	m.pingScan = false
	m.traceroute = false
	m.skipDiscovery = false
		// page 3
	m.scanTechnique = tcpSyn
		// page 4
	m.versionDetection = true
	m.versionIntensity  = 3,
		// page 5
	m.osDetection = false
	m.osScanLimit = false
	m.osScanGuess = false
		// page 6
	m.outputFormat = normal
	m.verbosityLevel = 0
	m.debugLevel = 0
	m.showReasonPortState = false
	m.openPortsOnly = false
	m.outputFile := t
	m.outputFile.Placeholder = "File to save the output"
	m.err = nil



	return m
}

func main() {
	p := tea.NewProgram(initialModel())
	values, err := p.Run()
	if err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
	fmt.Println(values)
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

