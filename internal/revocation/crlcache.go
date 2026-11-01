package revocation

import (
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Cache bounds.
const (
	DefaultCRLCacheBytes = 128 << 20
	crlCacheMaxAge       = time.Hour
)

func issuerKey(issuer *x509.Certificate) string {
	s := sha256.Sum256(issuer.Raw)
	return hex.EncodeToString(s[:])
}

// crlCache caches parsed CRLs keyed by (issuer SHA-256, URL) until
// min(nextUpdate, fetched+1h). Each costs ParsedCRL.Cost; the least
// recently used entries are evicted past the bound. Fetch+parse run once per
// key under singleflight, detached from any single caller's cancellation.
type crlCache struct {
	mu    sync.Mutex
	items map[string]*list.Element
	lru   *list.List
	cost  int64
	limit int64
	sf    singleflight.Group
}

type crlItem struct {
	key     string
	crl     *ParsedCRL
	expires time.Time
	cost    int64
}

func newCRLCache(limit int64) *crlCache {
	return &crlCache{items: make(map[string]*list.Element), lru: list.New(), limit: limit}
}

func (c *crlCache) get(key string, now time.Time) (*ParsedCRL, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	it := el.Value.(*crlItem)
	if !now.Before(it.expires) {
		c.removeLocked(el)
		return nil, false
	}
	c.lru.MoveToFront(el)
	return it.crl, true
}

func (c *crlCache) put(key string, p *ParsedCRL, now time.Time) {
	expires := now.Add(crlCacheMaxAge)
	if p.NextUpdate.Before(expires) {
		expires = p.NextUpdate
	}
	cost := p.Cost
	if cost > c.limit || !now.Before(expires) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.removeLocked(el)
	}
	c.items[key] = c.lru.PushFront(&crlItem{key: key, crl: p, expires: expires, cost: cost})
	c.cost += cost
	for c.cost > c.limit {
		c.removeLocked(c.lru.Back())
	}
}

func (c *crlCache) removeLocked(el *list.Element) {
	it := el.Value.(*crlItem)
	c.lru.Remove(el)
	delete(c.items, it.key)
	c.cost -= it.cost
}

type crlLoad struct {
	crl     *ParsedCRL
	status  Status
	attempt Attempt
	err     error
}

// load returns the cached CRL or fetches it once for all concurrent callers.
func (c *crlCache) load(ctx context.Context, key string, now time.Time, timeout time.Duration, fetch func(context.Context) crlLoad) crlLoad {
	if p, ok := c.get(key, now); ok {
		return crlLoad{crl: p, status: StatusGood, attempt: Attempt{Method: MethodCRL, URL: p.URL, FromCache: true}}
	}
	ch := c.sf.DoChan(key, func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		res := fetch(fctx)
		if res.err == nil && res.crl != nil {
			c.put(key, res.crl, now)
		}
		return res, nil
	})
	select {
	case r := <-ch:
		return r.Val.(crlLoad)
	case <-ctx.Done():
		return crlLoad{status: StatusUnavailable, err: ctx.Err(), attempt: Attempt{Method: MethodCRL, Outcome: StatusUnavailable, Detail: "cancelled while waiting for CRL fetch"}}
	}
}
