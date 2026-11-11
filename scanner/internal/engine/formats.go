package engine

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func detectType(path string, b []byte) string {
	if len(b) >= 4 {
		switch {
		case bytes.HasPrefix(b, []byte{0x7f, 'E', 'L', 'F'}):
			return "elf"
		case bytes.HasPrefix(b, []byte{'M', 'Z'}):
			return "pe"
		case bytes.HasPrefix(b, []byte{'P', 'K', 3, 4}), bytes.HasPrefix(b, []byte{'P', 'K', 5, 6}), bytes.HasPrefix(b, []byte{'P', 'K', 7, 8}):
			return "zip"
		case bytes.HasPrefix(b, []byte{'%', 'P', 'D', 'F', '-'}):
			return "pdf"
		case bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}):
			return "png"
		case bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}):
			return "jpeg"
		case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
			return "gif"
		case bytes.HasPrefix(b, []byte{0x1f, 0x8b}):
			return "gzip"
		case bytes.HasPrefix(b, []byte{'R', 'a', 'r', '!', 0x1a, 7}):
			return "rar"
		case bytes.HasPrefix(b, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}):
			return "7z"
		case bytes.HasPrefix(b, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}):
			return "ole"
		case bytes.HasPrefix(b, []byte("SQLite format 3")):
			return "sqlite"
		case bytes.HasPrefix(b, []byte("RIFF")):
			return "riff"
		case bytes.HasPrefix(b, []byte("ID3")):
			return "mp3"
		}
		if len(b) >= 8 && bytes.Equal(b[4:8], []byte("ftyp")) {
			return "mp4"
		}
		m := binary.BigEndian.Uint32(b[:4])
		if m == 0xfeedface || m == 0xcefaedfe || m == 0xfeedfacf || m == 0xcffaedfe || m == 0xcafebabe {
			return "macho"
		}
	}
	if len(b) > 262 && bytes.Equal(b[257:262], []byte("ustar")) {
		return "tar"
	}
	ext := strings.ToLower(filepath.Ext(path))
	if utf8.Valid(b) && bytes.IndexByte(b, 0) == -1 {
		if ext == ".svg" {
			return "svg"
		}
		if ext == ".json" {
			return "json"
		}
		if ext == ".xml" {
			return "xml"
		}
		if len(b) > 0 && (bytes.HasPrefix(b, []byte("#!/")) || ext == ".sh" || ext == ".ps1" || ext == ".bat" || ext == ".js" || ext == ".py" || ext == ".cs" || ext == ".go") {
			return "script"
		}
		return "text"
	}
	if len(b) == 0 {
		return "empty"
	}
	return "binary"
}
func embeddedExecutableOffset(b []byte) int {
	if len(b) <= 64 {
		return -1
	}
	for _, sig := range [][]byte{{'M', 'Z'}, {0x7f, 'E', 'L', 'F'}} {
		i := bytes.Index(b[64:], sig)
		if i >= 0 {
			return i + 64
		}
	}
	return -1
}
func isContainer(kind string) bool { return kind == "zip" || kind == "tar" || kind == "gzip" }
