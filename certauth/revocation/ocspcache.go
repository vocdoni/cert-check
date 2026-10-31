package revocation

import (
	"container/list"
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

type ocspItem struct {
	key    string
	ev     OCSPEvidence
	status Status
	source string
}

func newOCSPCache(limit int) *ocspCache {
	return &ocspCache{items: make(map[string]*list.Element), lru: list.New(), limit: limit}
}

// get returns a cached answer still usable at now: good only while
// now − thisUpdate < min(5 min, nextUpdate − now); revoked until nextUpdate.
func (c *ocspCache) get(key string, now time.Time) (ocspItem, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return ocspItem{}, false
	}
	it := el.Value.(*ocspItem)
	s := it.ev.Single
	usable := false
	switch it.status {
	case StatusGood:
		ttl := ocspGoodMaxAge
		if !s.NextUpdate.IsZero() && s.NextUpdate.Sub(now) < ttl {
			ttl = s.NextUpdate.Sub(now)
		}
		age := now.Sub(s.ThisUpdate)
		usable = age >= -ClockSkew && age < ttl
	case StatusRevoked:
		usable = !s.NextUpdate.IsZero() && now.Before(s.NextUpdate)
	}
	if !usable {
		c.lru.Remove(el)
		delete(c.items, key)
		return ocspItem{}, false
	}
	c.lru.MoveToFront(el)
	return *it, true
}

func (c *ocspCache) put(it ocspItem) {
	if it.status != StatusGood && it.status != StatusRevoked {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[it.key]; ok {
		c.lru.Remove(el)
	}
	c.items[it.key] = c.lru.PushFront(&it)
	for c.lru.Len() > c.limit {
		back := c.lru.Back()
		c.lru.Remove(back)
		delete(c.items, back.Value.(*ocspItem).key)
	}
}
