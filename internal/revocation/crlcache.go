package revocation

import (
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Cache bounds.
const (
	DefaultCRLCacheBytes = 128 << 20
	crlCacheMaxAge       = time.Hour
	crlMaxMarks          = 4096
)

var (
	errCRLRollback = errors.New("crl number rolled back")
	errCRLPanic    = errors.New("crl fetch failed: internal error")
)

func issuerKey(issuer *x509.Certificate) string {
	s := sha256.Sum256(issuer.Raw)
	return hex.EncodeToString(s[:])
}

// crlCache caches parsed CRLs keyed by (issuer SHA-256, URL) until
// min(nextUpdate, fetched+1h). Each costs ParsedCRL.Cost; the least
// recently used entries are evicted past the bound. Fetch+parse run once per
// key under singleflight, detached from any single caller's cancellation.
// The highest CRL number seen per key outlives the entries, so a replayed
// older CRL is rejected after the newer one expired from the cache.
type crlCache struct {
	mu    sync.Mutex
	items map[string]*list.Element
	lru   *list.List
	cost  int64
	limit int64
	sf    singleflight.Group

	marks    map[string]*list.Element // key -> *crlMark; outlives items
	markList *list.List
}

// crlMark is the highest CRL number admitted for a key.
type crlMark struct {
	key    string
	number *big.Int
}

type crlItem struct {
	key     string
	crl     *ParsedCRL
	expires time.Time
	cost    int64
}

func newCRLCache(limit int64) *crlCache {
	return &crlCache{items: make(map[string]*list.Element), lru: list.New(), limit: limit,
		marks: make(map[string]*list.Element), markList: list.New()}
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

// raiseMark makes number the high-water mark of key, unless it is below the
// mark (a rolled-back CRL); a CRL without a number leaves the mark alone.
// The least recently raised marks are evicted past crlMaxMarks.
func (c *crlCache) raiseMark(key string, number *big.Int) bool {
	if number == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.marks[key]; ok {
		m := el.Value.(*crlMark)
		if number.Cmp(m.number) < 0 {
			return false
		}
		m.number = number
		c.markList.MoveToFront(el)
		return true
	}
	c.marks[key] = c.markList.PushFront(&crlMark{key: key, number: number})
	if c.markList.Len() > crlMaxMarks {
		back := c.markList.Back()
		c.markList.Remove(back)
		delete(c.marks, back.Value.(*crlMark).key)
	}
	return true
}

type crlLoad struct {
	crl     *ParsedCRL
	status  Status
	attempt Attempt
	err     error
	admit   bool // crl is fresh and issued for the DP of its URL: it may be cached
}

// load returns the cached CRL or fetches it once for all concurrent callers.
// Only an admitted CRL is cached and raises the CRL-number mark of key; one
// numbered below the mark is invalid evidence. A caller already cancelled
// starts no fetch, and a panic in the fetch is an unavailable result: under
// DoChan singleflight would re-raise it where nothing can recover it.
func (c *crlCache) load(ctx context.Context, key string, now time.Time, timeout time.Duration, fetch func(context.Context) crlLoad) crlLoad {
	if p, ok := c.get(key, now); ok {
		return crlLoad{crl: p, status: StatusGood, attempt: Attempt{Method: MethodCRL, URL: p.URL, FromCache: true}}
	}
	if err := ctx.Err(); err != nil {
		return crlLoad{status: StatusUnavailable, err: err, attempt: Attempt{Method: MethodCRL, Outcome: StatusUnavailable, Detail: "cancelled before CRL fetch"}}
	}
	ch := c.sf.DoChan(key, func() (v any, _ error) {
		defer func() {
			if recover() != nil {
				v = crlLoad{status: StatusUnavailable, err: errCRLPanic, attempt: Attempt{Method: MethodCRL}}
			}
		}()
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		res := fetch(fctx)
		if res.err == nil && res.crl != nil && res.admit {
			if !c.raiseMark(key, res.crl.Number) {
				return crlLoad{status: StatusInvalidEvidence, err: errCRLRollback, attempt: res.attempt}, nil
			}
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
