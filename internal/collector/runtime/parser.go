// Package runtime inventories explicitly opted-in point-in-time developer
// process and listener facts. It does not continuously monitor the host.
package runtime

import (
	"bufio"
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var errRuntimeOutput = errors.New("runtime probe output is malformed")

const maxRuntimeOutputBytes = 4 << 20

type processFact struct {
	PID        int
	Executable string
}

type listenerFact struct {
	PID      int
	Protocol string
	Port     int
}

func parseProcessSnapshot(output string) ([]processFact, error) {
	if len(output) > maxRuntimeOutputBytes || !utf8.ValidString(output) {
		return nil, errRuntimeOutput
	}
	byPID := make(map[int]processFact)
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 4096), maxRuntimeOutputBytes+1)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			return nil, errRuntimeOutput
		}
		pid, err := strconv.Atoi(fields[0])
		executable, ok := normalizedExecutableName(fields[1])
		if err != nil || pid <= 0 || !ok {
			return nil, errRuntimeOutput
		}
		fact := processFact{PID: pid, Executable: executable}
		if existing, duplicate := byPID[pid]; duplicate && existing != fact {
			return nil, errRuntimeOutput
		}
		byPID[pid] = fact
	}
	if scanner.Err() != nil {
		return nil, errRuntimeOutput
	}
	facts := make([]processFact, 0, len(byPID))
	for _, fact := range byPID {
		facts = append(facts, fact)
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].PID < facts[j].PID })
	return facts, nil
}

func normalizedExecutableName(value string) (string, bool) {
	name := filepath.Base(value)
	if name == "" || name == "." || name == string(filepath.Separator) || len(name) > 255 {
		return "", false
	}
	for _, character := range name {
		if unicode.IsControl(character) || unicode.IsSpace(character) || strings.ContainsRune(`/\:`, character) {
			return "", false
		}
	}
	return name, true
}

func parseListenerSnapshot(output string) ([]listenerFact, error) {
	if len(output) > maxRuntimeOutputBytes || !utf8.ValidString(output) {
		return nil, errRuntimeOutput
	}
	currentPID := 0
	seen := make(map[listenerFact]struct{})
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 4096), maxRuntimeOutputBytes+1)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			return nil, errRuntimeOutput
		}
		switch line[0] {
		case 'p':
			pid, err := strconv.Atoi(line[1:])
			if err != nil || pid <= 0 {
				return nil, errRuntimeOutput
			}
			currentPID = pid
		case 'c':
			if _, ok := normalizedExecutableName(line[1:]); !ok {
				return nil, errRuntimeOutput
			}
		case 'n':
			if currentPID == 0 {
				return nil, errRuntimeOutput
			}
			port, ok := listenerPort(line[1:])
			if !ok {
				return nil, errRuntimeOutput
			}
			seen[listenerFact{PID: currentPID, Protocol: "tcp", Port: port}] = struct{}{}
		default:
			return nil, errRuntimeOutput
		}
	}
	if scanner.Err() != nil {
		return nil, errRuntimeOutput
	}
	facts := make([]listenerFact, 0, len(seen))
	for fact := range seen {
		facts = append(facts, fact)
	}
	sort.Slice(facts, func(i, j int) bool {
		if facts[i].PID != facts[j].PID {
			return facts[i].PID < facts[j].PID
		}
		return facts[i].Port < facts[j].Port
	})
	return facts, nil
}

func listenerPort(value string) (int, bool) {
	if strings.Contains(value, "->") {
		return 0, false
	}
	index := strings.LastIndexByte(value, ':')
	if index < 0 || index == len(value)-1 {
		return 0, false
	}
	port, err := strconv.Atoi(value[index+1:])
	return port, err == nil && port > 0 && port <= 65535
}
