package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

func safeMember(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) {
		return false
	}
	for _, s := range strings.Split(name, "/") {
		if s == ".." || s == "." || s == "" {
			return false
		}
	}
	return true
}
func (r *Report) inspectMember(name string, reader io.Reader, size int64, depth int) {
	if size < 0 {
		r.Uninspected(name, "invalid archive entry size", true, size)
		return
	}
	if r.EmbeddedSeen >= MaxArchiveEntries {
		r.Uninspected(name, "archive entry count limit", true, size)
		r.warn("Archive entry count exceeds safety limit.")
		return
	}
	if !safeMember(strings.Split(name, "!")[len(strings.Split(name, "!"))-1]) {
		r.Uninspected(name, "unsafe archive member path", true, size)
		return
	}
	// Always account for entry; cap consumption and note partial inspection.
	data, err := io.ReadAll(io.LimitReader(reader, MaxFileBytes+1))
	if err != nil {
		r.Uninspected(name, "archive entry read error", true, size)
		return
	}
	ScanFile(r, name, data, size, true, depth)
}
func scanContainer(report *Report, name string, data []byte, kind string, depth int) {
	if kind == "zip" {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			report.warn("Invalid ZIP container: " + name)
			report.Truncated = true
			return
		}
		var budget int64
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			child := name + "!" + f.Name
			if strings.EqualFold(path.Base(f.Name), "vbaProject.bin") {
				report.add(Finding{"DOC003", "Document threats", "Office macro project in archive", "medium", "A document archive contains a VBA macro project; macro presence does not prove maliciousness.", child, 0, "[VBA project entry]", 8})
			}
			if f.Mode()&os.ModeSymlink != 0 {
				report.Uninspected(child, "archive symlink is not followed", true, int64(f.UncompressedSize64))
				continue
			}
			if !safeMember(f.Name) {
				report.Uninspected(child, "unsafe archive member path", true, int64(f.UncompressedSize64))
				continue
			}
			size := int64(f.UncompressedSize64)
			if size < 0 || budget+size > MaxArchiveUnpackedBytes {
				report.Uninspected(child, "archive uncompressed byte budget reached", true, size)
				report.warn("Archive expansion limit reached.")
				continue
			}
			budget += size
			if f.Flags&1 != 0 {
				report.Uninspected(child, "encrypted ZIP member", true, size)
				continue
			}
			if report.BytesScanned >= MaxTotalBytes {
				report.Uninspected(child, "scan-wide resource limit reached", true, size)
				continue
			}
			rdr, e := f.Open()
			if e != nil {
				report.Uninspected(child, "ZIP member cannot be opened", true, size)
				continue
			}
			report.inspectMember(child, rdr, size, depth)
			rdr.Close()
		}
		return
	}
	if kind == "gzip" {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			report.warn("Corrupt gzip container: " + name)
			report.Truncated = true
			return
		}
		defer gz.Close()
		// gzip may wrap a tar stream or one file. Limit expanded size before inspection.
		expanded, err := io.ReadAll(io.LimitReader(gz, MaxFileBytes+1))
		if err != nil {
			report.warn("Error reading gzip: " + name)
			report.Truncated = true
			return
		}
		child := name + "!" + strings.TrimSuffix(path.Base(name), ".gz")
		if len(expanded) > MaxFileBytes {
			report.Uninspected(child, "gzip output exceeds expanded-file limit", true, int64(len(expanded)))
			return
		}
		if detectType(child, expanded) == "tar" {
			scanContainer(report, name, expanded, "tar", depth)
			return
		}
		ScanFile(report, child, expanded, int64(len(expanded)), true, depth)
		return
	}
	if kind == "tar" {
		tr := tar.NewReader(bytes.NewReader(data))
		var budget int64
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				report.warn("Malformed TAR: " + name)
				report.Truncated = true
				break
			}
			if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
				if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
					report.Uninspected(name+"!"+hdr.Name, "archive link not followed", true, 0)
				}
				continue
			}
			child := name + "!" + hdr.Name
			if !safeMember(hdr.Name) {
				report.Uninspected(child, "unsafe archive member path", true, hdr.Size)
				continue
			}
			if hdr.Size < 0 || budget+hdr.Size > MaxArchiveUnpackedBytes {
				report.Uninspected(child, "TAR expansion budget reached", true, hdr.Size)
				continue
			}
			budget += hdr.Size
			report.inspectMember(child, tr, hdr.Size, depth)
		}
		return
	}
	report.warn(fmt.Sprintf("No specialized parser for container type %s", kind))
}
