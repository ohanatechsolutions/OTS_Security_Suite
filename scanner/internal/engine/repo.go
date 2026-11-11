package engine

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const MaxArchiveBytes = 60 << 20

var ownerRepo = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

// ParseRepo intentionally rejects private domains and unexpected URL paths (SSRF protection).
func ParseRepo(input string) (host, owner, repo string, err error) {
	input = strings.TrimSpace(input)
	if !strings.Contains(input, "://") {
		input = "https://" + input
	}
	u, e := url.Parse(input)
	if e != nil {
		return "", "", "", e
	}
	if u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return "", "", "", errors.New("only public HTTPS GitHub/Bitbucket URLs are supported")
	}
	host = strings.ToLower(u.Hostname())
	if host != "github.com" && host != "www.github.com" && host != "bitbucket.org" {
		return "", "", "", errors.New("only github.com and bitbucket.org are supported")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", "", errors.New("expected owner/repo URL")
	}
	owner = parts[0]
	repo = strings.TrimSuffix(parts[1], ".git")
	if !ownerRepo.MatchString(owner) || !ownerRepo.MatchString(repo) || owner == "." || repo == "." || strings.Contains(owner, "..") || strings.Contains(repo, "..") {
		return "", "", "", errors.New("invalid repository owner or name")
	}
	if host == "www.github.com" {
		host = "github.com"
	}
	return host, owner, repo, nil
}

func ScanRemote(input string) (*Report, error) {
	host, owner, repo, err := ParseRepo(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	var download string
	if host == "github.com" {
		download = "https://api.github.com/repos/" + owner + "/" + repo + "/tarball"
	} else {
		download = "https://bitbucket.org/" + owner + "/" + repo + "/get/HEAD.tar.gz"
	}
	client := &http.Client{Timeout: 95 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 4 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("insecure redirect refused")
		}
		h := strings.ToLower(req.URL.Hostname())
		if h != "api.github.com" && h != "codeload.github.com" && h != "github.com" && h != "bitbucket.org" && h != "api.bitbucket.org" {
			return fmt.Errorf("unexpected archive redirect host: %s", h)
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", download, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "OTS-GitHub-Malware-Scanner/2.0")
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("repository download failed: HTTP %d (public repos only; rate limits apply)", res.StatusCode)
	}
	if res.ContentLength > MaxArchiveBytes {
		return nil, errors.New("repository snapshot is larger than 60 MB")
	}
	// Limit compressed bytes, then reject archives that cannot terminate within bound.
	compressed := io.LimitReader(res.Body, MaxArchiveBytes+1)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, fmt.Errorf("invalid repository archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	report := NewReport("https://"+host+"/"+owner+"/"+repo, "public repository")
	entries := 0
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("invalid tar archive: %w", e)
		}
		entries++
		if entries > 50000 {
			report.Truncated = true
			break
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
				report.Uninspected(hdr.Name, "repository archive link not followed", false, 0)
			}
			continue
		} // never follow links / execute files
		name := hdr.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		} // strip archive commit prefix
		if name == "" {
			continue
		}
		if hdr.Size < 0 {
			report.Uninspected(name, "invalid repository archive size", false, hdr.Size)
			continue
		}
		// Do not skip based on extension. A size limit gives partial coverage, not silence.
		if report.BytesScanned >= MaxTotalBytes || report.FilesSeen+report.EmbeddedSeen >= MaxFiles {
			report.Uninspected(name, "scan-wide resource limit reached", false, hdr.Size)
			continue
		}
		data, e := io.ReadAll(io.LimitReader(tr, MaxFileBytes+1))
		if e != nil {
			report.Uninspected(name, "could not read repository file", false, hdr.Size)
			continue
		}
		ScanFile(report, name, data, hdr.Size, false, 0)

	}
	report.warn("A source archive represents one revision; it does not include Git history, submodule contents, or Git LFS binary content unless bundled. These require separate collection.")
	Finalize(report)
	return report, nil
}
