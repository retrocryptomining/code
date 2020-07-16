package scanner

import (
	"crypto/sha1"
	"strconv"

	"github.com/hashicorp/golang-lru"
	"log"
)

const (
	WebRootType = iota
	JSFileType = iota
)

const (
	MiningJSFilenameWebroot 	= iota
	MiningJSFilenameLinkedJS	= iota

	MiningURLPatternWebroot 	= iota
	MiningURLPatternLinkedJS 	= iota

	MiningKeywordInlineJS   	= iota
	MiningKeywordLinkedJS   	= iota

	ObfuscatedInlineJS      	= iota
	ObfuscatedLinkedJS      	= iota
)



func ResultToString(r int) string {

	switch {
	case r == MiningJSFilenameWebroot:
		return "MINING_JS_FILENAME_WEBROOT"
	case r == MiningJSFilenameLinkedJS:
		return "MINING_JS_FILENAME_LINKED_JS"

	case r == MiningURLPatternWebroot:
		return "MINING_URL_PATTERN_WEBROOT"
	case r == MiningURLPatternLinkedJS:
		return "MINING_URL_PATTERN_LINKED_JS"

	case r == MiningKeywordInlineJS:
		return "MINING_KEYWORD_IN_INLINE_JS"
	case r == MiningKeywordLinkedJS:
		return "MINING_KEYWORD_IN_LINKED_JS"

	case r == ObfuscatedInlineJS:
		return "OBFUSCATED_INLINE_JS"
	case r == ObfuscatedLinkedJS:
		return "OBFUSCATED_LINKED_JS"
	}

	return "UNKNOWN"
}



func LogResultToString(found bool, r int) string {

	if found {
		return "FOUND_" + ResultToString(r) + ": %s, %s"
	} else {
		return "NO_" + ResultToString(r) + ": %s, %s"
	}
}



type URLInput struct {
	FullURL		string
	Host 		string
	Scheme 		string
	Type		int
}


// URLResult struct to be passed through channels.
type URLResult struct {
	FullURL		string
	Host      	string
	InputType 	int
	Hitlist   	string
	LastRequest string
	Msg       	int
	Page      	*[]byte
	Scheme    	string
	StatusCode	string
	Success   	bool
	Timestamp 	int64
}



func (r *URLResult) toRecord() []string {
	record := []string {
		strconv.FormatInt(r.Timestamp, 10),
		r.Scheme,
		r.Host,
		strconv.FormatBool(r.Success),
		r.Hitlist,
		r.LastRequest,
		r.StatusCode,
		ResultToString(r.Msg),
	}
	return record
}



// URLCache stores URLs we have already visited. It is concurrency-safe.
type URLCache struct {
	cache 	*lru.Cache
}


func NewURLCache(size int) *URLCache {
	lruCache, err := lru.New(size)
	if err != nil {
		log.Fatalf("Could not create LRU cache for JS URLs: %s", err)
	}
	return &URLCache{
		cache: lruCache,
	}
}


// contains() returns whether a URL is in the cache or not
func (c *URLCache) contains(url string) bool {
	return c.cache.Contains(url)
}


// containsOrAdd() adds a URL (as a string) to URLCache. If the URL is already
// in the cache, it returns true. If it did not exist in the cache yet, it returns false.
func (c *URLCache) containsOrAdd(url string, status int) bool {
	s := sha1.Sum([]byte(url))
	sha1Sum := string(s[:])

	inCache, _ := c.cache.ContainsOrAdd(sha1Sum, status)

	return inCache
}

// peek() returns the status for a URL in the cache (or nil if not found).
func (c *URLCache) peek(url string) (int, bool) {
	s := sha1.Sum([]byte(url))
	sha1Sum := string(s[:])

	statusI, ok := c.cache.Peek(sha1Sum)

	if !ok {
		return -1, false
	}

	return statusI.(int), ok
}
