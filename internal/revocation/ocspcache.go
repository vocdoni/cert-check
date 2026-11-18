package revocation

import (
	"container/list"
	"net/url"
	"sync"
	"time"
)

// OCSP cache bounds.
const (
	DefaultOCSPCacheEntries = 4096
	ocspGoodMaxAge          = 5 * time.Minute
)

// ocspCache caches accepted good and revoked OCSP answers by (issuer SHA-256, serial).
type ocspCache struct {
	mu    sync.Mutex
	items map[string]*list.Element
	lru   *list.List
	limit int
}

// ocspItem is the compact part of an accepted answer that the cache keeps.
// It holds no slice of the response, so an entry never pins the fetch buffer
// or a parsed certificate.
type ocspItem struct {
	key              string
	status           Status
	thisUpdate       time.Time
	nextUpdate       time.Time // zero when absent
	revokedAt        time.Time
	reason           int
	responderSubject string
	nonceEchoed      bool
	signerNotBefore  time.Time
	signerNotAfter   time.Time
	url              string // AIA URL that served the answer
	source           string // host of url
}

// newOCSPItem keeps the compact part of evidence ev, verified with status st,
// from url u.
func newOCSPItem(u string, st Status, ev OCSPEvidence) ocspItem {
	it := ocspItem{
		status: st, url: u, source: hostOf(u),
		thisUpdate: ev.Single.ThisUpdate, nextUpdate: ev.Single.NextUpdate,
		revokedAt: ev.Single.RevokedAt, reason: ev.Single.Reason,
		responderSubject: ev.ResponderSubject, nonceEchoed: ev.NonceEchoed,
	}
	if ev.Signer != nil {
		it.signerNotBefore, it.signerNotAfter = ev.Signer.NotBefore, ev.Signer.NotAfter
	}
	return it
}

func newOCSPCache(limit int) *ocspCache {
	return &ocspCache{items: make(map[string]*list.Element), lru: list.New(), limit: limit}
}

// get returns a cached answer still usable at now under policy p.
func (c *ocspCache) get(key string, now time.Time, p Policy) (ocspItem, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return ocspItem{}, false
	}
	it := el.Value.(*ocspItem)
	if !it.usable(now, p) {
		c.lru.Remove(el)
		delete(c.items, key)
		return ocspItem{}, false
	}
	c.lru.MoveToFront(el)
	return *it, true
}

// usable reports whether the answer may be reused at now under policy p:
// good only while now − thisUpdate < min(5 min, nextUpdate − now), or
// min(5 min, p.MaxAge()) without nextUpdate; revoked until nextUpdate. In
// both cases only while the signer is valid, and only when p would accept
// the answer fresh: a nonce echoed if p requires one, the URL on p's OCSP
// allowlist.
func (it *ocspItem) usable(now time.Time, p Policy) bool {
	if now.Before(it.signerNotBefore) || !now.Before(it.signerNotAfter) || p.OCSPNonce && !it.nonceEchoed {
		return false
	}
	if u, err := url.Parse(it.url); err != nil || !hostAllowed(u, p.OCSPHosts) {
		return false
	}
	switch it.status {
	case StatusGood:
		ttl := ocspGoodMaxAge
		if it.nextUpdate.IsZero() {
			ttl = min(ttl, p.MaxAge())
		} else {
			ttl = min(ttl, it.nextUpdate.Sub(now))
		}
		age := now.Sub(it.thisUpdate)
		return age >= -ClockSkew && age < ttl
	case StatusRevoked:
		return !it.nextUpdate.IsZero() && now.Before(it.nextUpdate)
	}
	return false
}

func (c *ocspCache) put(key string, it ocspItem) {
	if it.status != StatusGood && it.status != StatusRevoked {
		return
	}
	it.key = key
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.lru.Remove(el)
	}
	c.items[key] = c.lru.PushFront(&it)
	for c.lru.Len() > c.limit {
		back := c.lru.Back()
		c.lru.Remove(back)
		delete(c.items, back.Value.(*ocspItem).key)
	}
}
