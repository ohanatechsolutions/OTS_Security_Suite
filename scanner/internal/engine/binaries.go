package engine

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"strings"
)

func binaryInspection(r *Report, filename string, data []byte, kind string) {
	switch kind {
	case "pe":
		f, err := pe.NewFile(bytes.NewReader(data))
		if err != nil {
			r.warn("Some PE files could not be structurally parsed; baseline inspection still completed.")
			return
		}
		defer f.Close()
		imports, err := f.ImportedSymbols()
		if err != nil {
			r.warn("PE imports could not be fully resolved for every executable.")
		}
		joined := strings.ToLower(strings.Join(imports, "|"))
		if strings.Contains(joined, "createremotethread") && strings.Contains(joined, "writeprocessmemory") {
			r.add(Finding{"BIN001", "Host control", "PE imports support process injection", "high", "Combined CreateRemoteThread and WriteProcessMemory imports indicate code-injection capability, which may also be legitimate.", filename, 0, "[PE import names]", 18})
		}
		if strings.Contains(joined, "cryptunprotectdata") && (strings.Contains(joined, "winhttpsendrequest") || strings.Contains(joined, "httpsendrequest")) {
			r.add(Finding{"BIN002", "Credential theft", "PE combines decrypt and network upload APIs", "high", "A credential-decryption API and outbound HTTP API are both imported; requires manual review.", filename, 0, "[PE imports]", 16})
		}
		if strings.Contains(joined, "setwindowshookex") {
			r.add(Finding{"BIN003", "Host control", "PE imports keyboard or window hook APIs", "low", "Windows hook APIs can be used by hotkey utilities or monitoring tools.", filename, 0, "[PE imports]", 5})
		}
	case "elf":
		f, err := elf.NewFile(bytes.NewReader(data))
		if err != nil {
			r.warn("Some ELF files could not be structurally parsed; baseline inspection still completed.")
			return
		}
		defer f.Close()
		libs, _ := f.ImportedLibraries()
		for _, lib := range libs {
			if strings.Contains(strings.ToLower(lib), "libpcap") {
				r.add(Finding{"BIN004", "Host control", "ELF links to packet capture library", "low", "Network capture libraries can be used by security utilities or monitoring software.", filename, 0, "[ELF dynamic libraries]", 4})
				break
			}
		}
	case "macho":
		f, err := macho.NewFile(bytes.NewReader(data))
		if err != nil {
			r.warn("Some Mach-O files could not be structurally parsed; baseline inspection still completed.")
			return
		}
		defer f.Close()
	}
}

// Extract low-risk printable UTF-16 ASCII strings from native binaries for static rule matching.
// Both endiannesses are considered, bounded by the per-file byte budget.
func scanWideStrings(r *Report, filename string, data []byte) {
	count := 0
	for _, be := range []bool{false, true} {
		for start := 0; start+1 < len(data) && count < 2500; {
			i := start
			for i+1 < len(data) {
				x, y := data[i], data[i+1]
				if (be && (x != 0 || y < 32 || y > 126)) || (!be && (y != 0 || x < 32 || x > 126)) {
					break
				}
				i += 2
			}
			if i-start >= 16 {
				output := make([]byte, 0, (i-start)/2)
				for j := start; j < i && len(output) < 4096; j += 2 {
					if be {
						output = append(output, data[j+1])
					} else {
						output = append(output, data[j])
					}
				}
				scanIndicators(r, filename, output, 0)
				count++
			}
			if i > start {
				start = i
			} else {
				start++
			}
		}
	}
}
