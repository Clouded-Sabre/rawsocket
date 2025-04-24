//go:build darwin || freebsd || windows
// +build darwin freebsd windows

package lib

import (
	"log"
	"net"
	"sync"
	"time"
)

type ARPEntry struct {
	MacAddress net.HardwareAddr
	Expiry     time.Time
}

type ARPCache struct {
	mu           sync.RWMutex
	entries      map[string]ARPEntry
	timeout      time.Duration
	timeoutTimer *time.Timer
	stopChan     chan struct{}
	isClosed     bool
	wg           sync.WaitGroup
}

func NewARPCache(timeout time.Duration) *ARPCache {
	cache := &ARPCache{
		entries:      make(map[string]ARPEntry),
		timeout:      timeout,
		timeoutTimer: time.NewTimer(timeout),
		stopChan:     make(chan struct{}),
		wg:           sync.WaitGroup{},
	}
	cache.wg.Add(1)
	go cache.cleanup()
	return cache
}

func (cache *ARPCache) Add(ip string, mac net.HardwareAddr) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.entries[ip] = ARPEntry{
		MacAddress: mac,
		Expiry:     time.Now().Add(cache.timeout),
	}
	if Debug {
		log.Printf("ARPCache: Added IP %s -> MAC %s", ip, mac)
	}
}

func (cache *ARPCache) Lookup(ip string) (net.HardwareAddr, bool) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	entry, found := cache.entries[ip]
	if !found {
		if Debug {
			log.Printf("ARPCache: Miss for IP %s (not found)", ip)
		}
		return nil, false
	}
	if time.Now().After(entry.Expiry) {
		if Debug {
			log.Printf("ARPCache: Miss for IP %s (expired)", ip)
		}
		return nil, false
	}
	if Debug {
		log.Printf("ARPCache: Hit for IP %s -> MAC %s", ip, entry.MacAddress)
	}
	return entry.MacAddress, true
}

func (cache *ARPCache) cleanup() {
	defer cache.wg.Done()
	for {
		select {
		case <-cache.timeoutTimer.C:
			cache.mu.Lock()
			now := time.Now()
			// Collect expired IPs first
			var expiredIPs []string
			for ip, entry := range cache.entries {
				if now.After(entry.Expiry) {
					expiredIPs = append(expiredIPs, ip)
				}
			}
			// Delete expired entries
			for _, ip := range expiredIPs {
				delete(cache.entries, ip)
				if Debug {
					log.Printf("ARPCache: Removed expired IP %s", ip)
				}
			}

			if !cache.isClosed {
				cache.timeoutTimer.Reset(cache.timeout) // Align with cache.timeout
			}
			cache.mu.Unlock()
		case <-cache.stopChan:
			return
		}
	}
}

func (cache *ARPCache) Close() {
	cache.mu.Lock()
	if cache.isClosed {
		cache.mu.Unlock()
		return
	}
	cache.isClosed = true
	cache.timeoutTimer.Stop()
	cache.mu.Unlock()

	close(cache.stopChan)
	cache.wg.Wait()
	log.Println("ARPCache stopped.")
}
