package bundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

var (
	errUpdateRedirect = errors.New("update redirect rejected")
)

func latestPath(name string) string       { return "releases/latest/download/" + name }
func releasePath(tag, name string) string { return "releases/download/" + tag + "/" + name }

func validUpdateBase(base *url.URL) bool {
	return base != nil && base.Scheme == "https" && base.Host != "" && base.User == nil && base.RawQuery == "" && base.Fragment == "" &&
		strings.HasSuffix(base.Path, "/s1ns3nz0/ssc-init-ti/")
}

func (u Updater) fetch(ctx context.Context, relative string, limit int64, expectedName string) ([]byte, UpdateErrorCode) {
	response, requestCtx, cancel, code := u.open(ctx, relative, limit, expectedName)
	if code != UpdateErrorNone {
		return nil, code
	}
	defer cancel()
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, networkCode(ctx, requestCtx)
	}
	if int64(len(raw)) > limit {
		return nil, UpdateErrorResponseLimit
	}
	return raw, UpdateErrorNone
}

func (u Updater) fetchFile(ctx context.Context, relative string, limit int64, expectedName, destination string) (int64, [sha256.Size]byte, UpdateErrorCode) {
	response, requestCtx, cancel, code := u.open(ctx, relative, limit, expectedName)
	if code != UpdateErrorNone {
		return 0, [sha256.Size]byte{}, code
	}
	defer cancel()
	defer response.Body.Close()
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, [sha256.Size]byte{}, UpdateErrorActivationFailed
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(response.Body, limit+1))
	closeErr := file.Close()
	if copyErr != nil {
		return 0, [sha256.Size]byte{}, networkCode(ctx, requestCtx)
	}
	if closeErr != nil {
		return 0, [sha256.Size]byte{}, UpdateErrorActivationFailed
	}
	if written > limit {
		return 0, [sha256.Size]byte{}, UpdateErrorResponseLimit
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return written, digest, UpdateErrorNone
}

func (u Updater) open(ctx context.Context, relative string, limit int64, expectedName string) (*http.Response, context.Context, context.CancelFunc, UpdateErrorCode) {
	target, err := u.Base.Parse(relative)
	if err != nil || target.RawQuery != "" || !validFetchURL(target, u.Base, expectedName, target.Path) {
		return nil, nil, func() {}, UpdateErrorRedirectRejected
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		cancel()
		return nil, nil, func() {}, UpdateErrorNetwork
	}
	request.Header.Del("Authorization")
	request.Header.Del("Cookie")
	client := *u.Client
	client.Jar = nil
	priorRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 2 || !validFetchURL(req.URL, u.Base, expectedName, target.Path) {
			return errUpdateRedirect
		}
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
		if priorRedirect != nil {
			// A caller may impose stricter policy, but cannot relax this policy.
			if err := priorRedirect(req, via); err != nil {
				return err
			}
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		cancel()
		if ctx.Err() != nil {
			return nil, nil, func() {}, UpdateErrorCancellation
		}
		if errors.Is(err, errUpdateRedirect) {
			return nil, nil, func() {}, UpdateErrorRedirectRejected
		}
		return nil, nil, func() {}, UpdateErrorNetwork
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		cancel()
		return nil, nil, func() {}, UpdateErrorNetwork
	}
	if response.ContentLength > limit {
		response.Body.Close()
		cancel()
		return nil, nil, func() {}, UpdateErrorResponseLimit
	}
	return response, requestCtx, cancel, UpdateErrorNone
}

func networkCode(parent, _ context.Context) UpdateErrorCode {
	if parent.Err() != nil {
		return UpdateErrorCancellation
	}
	return UpdateErrorNetwork
}

func validFetchURL(target, base *url.URL, expectedName, sourcePath string) bool {
	if target == nil || target.Scheme != "https" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || path.Base(target.Path) != expectedName {
		return false
	}
	host := strings.ToLower(target.Hostname())
	if strings.EqualFold(target.Host, base.Host) {
		return target.Path == sourcePath && strings.HasPrefix(target.Path, base.Path+"releases/")
	}
	switch host {
	case "github.com":
		return strings.HasPrefix(target.Path, "/s1ns3nz0/ssc-init-ti/releases/")
	case "objects.githubusercontent.com", "github-releases.githubusercontent.com", "release-assets.githubusercontent.com":
		return true
	default:
		return false
	}
}
