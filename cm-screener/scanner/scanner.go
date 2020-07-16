package scanner

import (
	"errors"
	"fmt"
	"net/http"
	"io"
	"io/ioutil"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"crypto/tls"
	"net/url"

	"golang.org/x/net/html"
	log "github.com/sirupsen/logrus"
	"strconv"
)

type JobCounters struct {
	sync.Mutex
	activeJSJobs 	  int
	activeWebrootJobs int
	doneJSJobs        int
	doneWebrootJobs   int
}


type MinerScannerConfig struct {
	CacheSize               	int
	DoMiningKeywords        	bool
	DoObfuscation           	bool
	DumpPages               	bool
	FollowJSLinks           	bool
	JSConcurrency           	int
	MaxRedirects            	int
	MiningJSFilenameStrings 	[]string
	MiningKeywordsStrings   	[]string
	MiningURLPatternsStrings	[]string
	ObfuscationStrings      	[]string
	Timeout                 	int
	UserAgent               	string
	UseAMQP                 	bool
	WebrootConcurrency      	int
}



type MinerScanner struct {
	useAMQP                    		bool
	config                     		*MinerScannerConfig
	httpClient                 		*http.Client
	inputReaderChannel         		chan URLInput
	jsJobsChannel              		chan URLInput
	jobCounters                		JobCounters
	jsTokenChannel             		chan struct{}
	jsURLCache                 		*URLCache
	ldhSet                     		string
	miningJSFilenamesRegexList 		[]*regexp.Regexp
	miningKeywordsRegexList    		[]*regexp.Regexp
	miningURLPatternsRegexList 		[]*regexp.Regexp
	obfuscationRegexList       		[]*regexp.Regexp
	resultForwarderChannel     		chan *URLResult
	resultWriterChannel        		chan *URLResult
	scriptExtractRegex		   		*regexp.Regexp
	timeout                    		int
	userAgent                  		string
	webrootTokenChannel        		chan struct{}
}


func NewMinerScanner(inputChan chan URLInput, resultForwarderChan chan *URLResult, resultWriterChan chan *URLResult, msc *MinerScannerConfig) *MinerScanner {

	tr := &http.Transport {
		MaxIdleConns:    10,
		IdleConnTimeout: time.Duration(msc.Timeout / 4) * time.Second,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: time.Duration(msc.Timeout / 2) * time.Second,
	}

	httpClient := &http.Client {
		Timeout: time.Duration(msc.Timeout) * time.Second,
		Transport: tr,
	}

	miningJSRegexList := createRegexesFromStrings(msc.MiningJSFilenameStrings)
	miningKeywordsRegexList := createRegexesFromStrings(msc.MiningKeywordsStrings)
	miningURLPatternsRegexList := createRegexesFromStrings(msc.MiningURLPatternsStrings)
	obfuscationRegexList := createRegexesFromStrings(msc.ObfuscationStrings)

	scriptRegex, err := regexp.Compile("(?i)(?s)<script.*?>(.*?)</script>")
	if err != nil {
		log.Fatalf("Compilation of regex failed: %s", err)
	}

	minerScanner := MinerScanner{
		useAMQP:                    msc.UseAMQP,
		config:                     msc,
		inputReaderChannel:         inputChan,
		jsJobsChannel:              make(chan URLInput, msc.JSConcurrency),
		jsTokenChannel:             make(chan struct{}, msc.JSConcurrency),
		jsURLCache:                 NewURLCache(msc.CacheSize),
		ldhSet:                     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.:",
		miningJSFilenamesRegexList: miningJSRegexList,
		miningKeywordsRegexList:    miningKeywordsRegexList,
		miningURLPatternsRegexList: miningURLPatternsRegexList,
		obfuscationRegexList:       obfuscationRegexList,
		resultForwarderChannel: 	resultForwarderChan,
		resultWriterChannel:        resultWriterChan,
		scriptExtractRegex: 		scriptRegex,
		userAgent: 					msc.UserAgent,
		webrootTokenChannel:        make(chan struct{}, msc.WebrootConcurrency),
	}

	for i := 0; i < msc.JSConcurrency; i++ {
		minerScanner.jsTokenChannel <- struct{}{}
	}

	for i := 0; i < msc.WebrootConcurrency; i++ {
		minerScanner.webrootTokenChannel <- struct{}{}
	}

	httpClient.CheckRedirect = minerScanner.interceptRedirect
	minerScanner.httpClient = httpClient

	return &minerScanner

}


func (m *MinerScanner) Scan(scanWg *sync.WaitGroup) {

	var webrootJobsWg sync.WaitGroup
	var jsJobsWg sync.WaitGroup
	var channelReaderWg sync.WaitGroup

	// keep track of our jobs
	go func() {
		ticker := time.NewTicker(time.Second * 5)
		for range ticker.C {
			m.jobCounters.Lock()
			fmt.Printf("Current estimate of running webroot/JS/total jobs: %d/%d/%d\n",
				m.jobCounters.activeWebrootJobs, m.jobCounters.activeJSJobs, m.jobCounters.activeWebrootJobs + m.jobCounters.activeJSJobs)
			fmt.Printf("Current estimate of finished webroot/JS/total jobs: %d/%d/%d\n",
				m.jobCounters.doneWebrootJobs, m.jobCounters.doneJSJobs, m.jobCounters.doneWebrootJobs + m.jobCounters.doneJSJobs)
			fmt.Println("")
			m.jobCounters.Unlock()
		}
	}()

	channelReaderWg.Add(1)
	go func() {
		for input := range m.inputReaderChannel {
			<- m.webrootTokenChannel
			webrootJobsWg.Add(1) // given back in TestURL()
			log.Debugf("Sending webroot job to TestURL: %s", input.Host)
			go m.TestURL(input, &webrootJobsWg)
		}
		log.Debugf("Finished reading from inputReader; waiting for webroot jobs to finish.")
		// we wait for all webroot jobs to return, so...
		webrootJobsWg.Wait()
		// ...we can close jsJobsChannel - only TestURL() can write into it.
		msg := "Finished webroot jobs."
		fmt.Println(msg)
		log.Debugf(msg)
		close(m.jsJobsChannel)
		channelReaderWg.Done()
	}()

	channelReaderWg.Add(1)
	go func() {
		for input := range m.jsJobsChannel {
			<- m.jsTokenChannel
			jsJobsWg.Add(1) // given back in TestURL()
			log.Debugf("Sending JS job to TestURL: %s", input.FullURL)
			go m.TestURL(input, &jsJobsWg)
		}
		log.Debugf("Finished reading from jsJobsChannel; waiting for JS jobs to finish.")
		jsJobsWg.Wait()
		msg := "Finished JS jobs."
		log.Debugf(msg)
		fmt.Println(msg)
		channelReaderWg.Done()
	}()

	channelReaderWg.Wait()

	log.Debugf("All jobs (webroot and JS) have finished; closing output channels.")
	close(m.resultWriterChannel)
	close(m.resultForwarderChannel)
	scanWg.Done()

}



func (m *MinerScanner) TestURL(urlInput URLInput, jobWg *sync.WaitGroup) {

	defer func() {
		if urlInput.Type == WebRootType {
			m.webrootTokenChannel <- struct{}{}
			m.jobCounters.Lock()
			m.jobCounters.activeWebrootJobs -= 1
			m.jobCounters.doneWebrootJobs += 1
			m.jobCounters.Unlock()
		}
		if urlInput.Type == JSFileType {
			m.jsTokenChannel <- struct{}{}
			m.jobCounters.Lock()
			m.jobCounters.activeJSJobs -= 1
			m.jobCounters.doneJSJobs +=1
			m.jobCounters.Unlock()
		}
		jobWg.Done()
	}()


	m.jobCounters.Lock()
	if urlInput.Type == WebRootType {
		m.jobCounters.activeWebrootJobs += 1
	}
	if urlInput.Type == JSFileType {
		m.jobCounters.activeJSJobs += 1
	}
	m.jobCounters.Unlock()

	var targetURL string


	if urlInput.Type == WebRootType {
		targetURL = urlInput.Scheme + urlInput.Host
	} else if urlInput.Type == JSFileType {
		targetURL = urlInput.FullURL
	} else {
		log.Fatalf("Unknown input type.")
	}



	// Create a request

	req, err := http.NewRequest("GET", targetURL, nil)
	req.Close = true
	req.Header.Set("User-Agent", m.userAgent)
	log.Debugf("Request created for: %s: %s", urlInput.Host, targetURL)

	if err != nil {
		log.Errorf("Request to %s could not be created: ", targetURL, err)
		return
	}

	// Connect to the host
	response, err := m.httpClient.Do(req)

	if err != nil {
		log.Errorf("Request to %s failed (full URL: %s): ", targetURL, urlInput.FullURL, err)
		return
	}

	// We need the URL that was used in the request that led to this response
	// - note that if we followed redirects, this will be a different request
	// than the one we created above.
	// We need this to deal to reconstruct relative URLs in the response HTML.
	lastRequestURL := response.Request.URL

	var page []byte

	// size up the slice if we know the content length - some domains send the max Int64 value (and beyond?)
	// for content-length, and that would make slice creation crash. We catch it here. Idiots.
	if response.ContentLength > 0  {
		if response.ContentLength >= math.MaxInt64 {
			log.Warningf("Content length outside of acceptable range: %d octets for %s", response.ContentLength, urlInput.Host)
			return
		} else if response.ContentLength > 2097152 {
			// if content length is larger than 2MB, we restrict ourselves to maximum that value. The site is not
			// very likely to send that much anyway as it's probably misconfigured.
			page = make([]byte, 2097152)
		} else {
			page = make([]byte, response.ContentLength)
		}
	}

	// catch pages that send too much data - we stop at 2MB
    page, err = ioutil.ReadAll(io.LimitReader(response.Body, 2097152))
    if len(page) == 2097152 {
    	log.Warningf("Site sent maximum allowed data: %s: %s", urlInput.Host, urlInput.FullURL)
	}

    if err != nil {
    	log.Warning("Unparseable reply for %s: %s - %s", urlInput.Host, urlInput.FullURL, err)
    	return
	}

    response.Body.Close()
    if urlInput.Type == JSFileType {
    	// print first 50 bytes of returned page to see if it is JS
		log.Debugf("Linked JS %s: %s", urlInput.FullURL, extractFirst50Bytes(string(page)))
	}
    pageString := string(page)

	// ==========================================================================================================
	// START FOLLOWING JS LINKS
	// If we want to follow links to JS files, we need to extract them. This means we have to parse the HTML.
	if urlInput.Type == WebRootType && m.config.FollowJSLinks {
		log.Debugf("Checking if there are linked JS files.")
		m.followJSLinks(lastRequestURL, &pageString, targetURL, &urlInput)
	}
	// END FOLLOWING JS LINKS
	// ==========================================================================================================






    // ==========================================================================================================
    // START TEST 1
    // a) If we see a filename of a known mining JS file anywhere in the page, we have a candidate, which
    // we send on to cm-validator. We always do this, on any webroot or linked JS file.
    var msg int
    if urlInput.Type == WebRootType {
		msg = MiningJSFilenameWebroot
	} else {
		msg = MiningJSFilenameLinkedJS
	}
	hitCount, hitList := m.checkForMiningJSFilename(&pageString)
	if hitCount == float64(0) {
		log.Debugf(LogResultToString(false, msg), urlInput.Host, targetURL)
	} else {
		res := URLResult{
			Host:        urlInput.Host,
			InputType:   urlInput.Type,
			Hitlist:     hitList,
			LastRequest: lastRequestURL.String(),
			Msg:         msg,
			Page:        &page,
			Scheme:      urlInput.Scheme,
			StatusCode:  strconv.Itoa(response.StatusCode),
			Success:     true,
			Timestamp:   time.Now().Unix(),
		}
		log.Infof(LogResultToString(true, res.Msg), urlInput.Host, urlInput.FullURL)
		m.resultWriterChannel <- &res
		if m.useAMQP {
			m.resultForwarderChannel <- &res
		}
		return
	}


	// b) If we see a filename of a known URL pattern anywhere in the page, we have a candidate, which
	// we send on to cm-validator. We always do this, on any webroot or linked JS file.
	if urlInput.Type == WebRootType {
		msg = MiningURLPatternWebroot
	} else {
		msg = MiningURLPatternLinkedJS
	}
	hitCount, hitList = m.checkForMiningURLPattern(&pageString)
	if hitCount == float64(0) {
		log.Debugf(LogResultToString(false, msg), urlInput.Host, targetURL)
	} else {
		res := URLResult{
			Host:        urlInput.Host,
			InputType:   urlInput.Type,
			Hitlist:     hitList,
			LastRequest: lastRequestURL.String(),
			Msg:         msg,
			Page:        &page,
			Scheme:      urlInput.Scheme,
			StatusCode:  strconv.Itoa(response.StatusCode),
			Success:     true,
			Timestamp:   time.Now().Unix(),
		}
		log.Infof(LogResultToString(true, res.Msg), urlInput.Host, urlInput.FullURL)
		m.resultWriterChannel <- &res
		if m.useAMQP {
			m.resultForwarderChannel <- &res
		}
		return
	}
	// END TEST 1
	// ==========================================================================================================


	// Preparation - we need to extract scripts if either keyword checking or obfuscation checking is enabled
	scripts := make([]string, 0)
	if m.config.DoMiningKeywords || m.config.DoObfuscation {
		scriptSlices := m.scriptExtractRegex.FindAllStringSubmatch(pageString, -1)
		// we ignore empty scripts
		for _, scriptSlice := range scriptSlices {
			script := strings.TrimSpace(scriptSlice[1])
			if script != "" {
				scripts = append(scripts, script)
			}
		}
	}

	// ==========================================================================================================
	// START TEST 2
	// If testing for mining keywords is enabled, we search in inline or linked JS. If we have a candidate, we send
	// the page to cm-validator.
	if m.config.DoMiningKeywords {

		if urlInput.Type == WebRootType {
			msg := MiningKeywordInlineJS

			for _, script := range scripts {
				hitCount, hitList := m.checkForMiningKeywords(&script)
				if hitCount == float64(0) {
						log.Debugf(LogResultToString(false, msg), urlInput.Host, urlInput.FullURL)
				} else {
					res := URLResult{
						Host:        urlInput.Host,
						InputType:   urlInput.Type,
						Hitlist:     hitList,
						LastRequest: lastRequestURL.String(),
						Msg: 		 msg,
						Page:        &page,
						Scheme:      urlInput.Scheme,
						StatusCode:  strconv.Itoa(response.StatusCode),
						Success:     true,
						Timestamp:   time.Now().Unix(),
					}
					log.Infof(LogResultToString(true, msg), urlInput.Host, urlInput.FullURL)
					m.resultWriterChannel <- &res
					if m.useAMQP {
						m.resultForwarderChannel <- &res
					}
					return
				}
			}

		}  else {
			msg := MiningKeywordLinkedJS

			hitCount, hitlist := m.checkForMiningKeywords(&pageString)
			if hitCount == float64(0) {
				log.Debugf(LogResultToString(false, msg), urlInput.Host, urlInput.FullURL)
			} else {
				res := URLResult{
					FullURL: 	 urlInput.FullURL,
					Host:        urlInput.Host,
					InputType:   urlInput.Type,
					Hitlist:     hitlist,
					LastRequest: lastRequestURL.String(),
					Msg:         msg,
					Page:        &page,
					Scheme:      urlInput.Scheme,
					StatusCode:  strconv.Itoa(response.StatusCode),
					Success:     true,
					Timestamp:   time.Now().Unix(),
				}
				m.jsURLCache.containsOrAdd(urlInput.FullURL, msg)
				log.Infof(LogResultToString(true, msg), urlInput.Host, urlInput.FullURL)
				m.resultWriterChannel <- &res
				if m.useAMQP {
					m.resultForwarderChannel <- &res
				}
				return
			}

		}

	}
	// END TEST 2
	// ==========================================================================================================



	// ==========================================================================================================
	// START TEST 3
	// If deobfuscation testing is enabled, we search in inline JS and linked JS. If we find a candidate, we send
	// to cm-detector. The result writer will also dump to disk.
	if m.config.DoObfuscation {

		if urlInput.Type == WebRootType {
			msg := ObfuscatedInlineJS

			for _, script := range scripts {
				hitCount, hitList := m.checkForObfuscation(&script)
				if hitCount == float64(0){
					log.Debugf(LogResultToString(false, msg), urlInput.Host, urlInput.FullURL)
				} else {
					res := URLResult{
						Host:        urlInput.Host,
						InputType:   urlInput.Type,
						Hitlist:     hitList,
						LastRequest: lastRequestURL.String(),
						Msg: 		 msg,
						Page:        &page,
						Scheme:      urlInput.Scheme,
						StatusCode:  strconv.Itoa(response.StatusCode),
						Success:     true,
						Timestamp:   time.Now().Unix(),
					}
					log.Infof(LogResultToString(true, msg), urlInput.Host, urlInput.FullURL)
					m.resultWriterChannel <- &res
					if m.useAMQP {
						m.resultForwarderChannel <- &res
					}
					return
				}
			}
		} else {
			msg := ObfuscatedLinkedJS

			hitCount, hitlist := m.checkForObfuscation(&pageString)
			if hitCount == float64(0) {
				log.Debugf(LogResultToString(false, msg), urlInput.Host, urlInput.FullURL)
			} else {
				res := URLResult{
					FullURL: 	 urlInput.FullURL,
					Host:        urlInput.Host,
					InputType:   urlInput.Type,
					Hitlist:     hitlist,
					LastRequest: lastRequestURL.String(),
					Msg:         msg,
					Page:        &page,
					Scheme:      urlInput.Scheme,
					StatusCode:  strconv.Itoa(response.StatusCode),
					Success:     true,
					Timestamp:   time.Now().Unix(),
				}
				m.jsURLCache.containsOrAdd(urlInput.FullURL, msg)
				log.Infof(LogResultToString(true, msg), urlInput.Host, urlInput.FullURL)
				m.resultWriterChannel <- &res
				if m.useAMQP {
					m.resultForwarderChannel <- &res
				}
			}
			return
		}

	}
	// END TEST 3
	// ==========================================================================================================

}








func (m *MinerScanner) applyRegexList(text *string, regexList []* regexp.Regexp) (float64, string) {

	var hitList []string
	hitCount := float64(0)

	for _, regex := range regexList {
		res := regex.FindString(strings.ToLower(*text))

		if res != "" {
			hitList = append(hitList, regex.String())
			hitCount += float64(1)
		}
	}

	return hitCount / float64(len(regexList)), strings.Join(hitList, ";")

}


// Check if input contains a known mining JS filename.
func (m *MinerScanner) checkForMiningJSFilename(input *string) (float64, string) {
	return m.applyRegexList(input, m.miningJSFilenamesRegexList)
}


// Check if input contains known mining keywords.
func (m *MinerScanner) checkForMiningKeywords(input *string) (float64, string) {
	return m.applyRegexList(input, m.miningKeywordsRegexList)
}


// Check if input contains a known WSS URL pattern
func (m *MinerScanner) checkForMiningURLPattern(input *string) (float64, string) {
	return m.applyRegexList(input, m.miningURLPatternsRegexList)
}


// Check if we are dealing with obfuscated JS
func (m *MinerScanner) checkForObfuscation(page *string) (float64, string) {
	return m.applyRegexList(page, m.obfuscationRegexList)
}


// Follow links to JS and create JS jobs
func (m *MinerScanner) followJSLinks(lastRequestURL *url.URL, pageString *string, targetURL string, urlInput *URLInput) {
	reader := strings.NewReader(*pageString)
	root, err := html.Parse(reader)
	// If the lib cannot fix the HTML, we give up
	if err != nil {
		log.Infof("HTML_TOO_BROKEN: ", targetURL)
		return
	}


	// the first thing we have to do is to check if there is a <base> tag used in the <head>.
	// We would need to interpret all URLs relative to its value.
	// Some sites set base to "/"; in this case we set it to the full URL of the site.
	baseHref := ""
	for c := root.FirstChild; c != nil; c = c.NextSibling {
		if strings.ToLower(c.Data) == "html" {
			for d := c.FirstChild; d != nil; d = d.NextSibling {
				if strings.ToLower(d.Data) == "head" {
					for t := d.FirstChild; t != nil; t = t.NextSibling {
						if strings.ToLower(t.Data) == "base" {
							for _, attr := range t.Attr {
								if strings.ToLower(attr.Key) == "href" {
									baseHref = attr.Val
									log.Debugf("Base tag detected: %s", urlInput.Host)
								}
							}
						}
					}
				}
			}
		}
	}

	if baseHref == "" {
		log.Debugf("No baseHref for %s", urlInput.Host)
	}

	// some sites set relative base refs
	if !strings.HasPrefix(baseHref, "http") {
		baseHref = urlInput.Scheme + urlInput.Host + "/" + baseHref
	}

	// we traverse the HTML tree now
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.ToLower(n.Data) == "script" {
			log.Debugf("Found script element for %s", urlInput.Host)
			var jsURL string
			isJSType := false
			for _, attr := range n.Attr {
				if strings.ToLower(attr.Key) == "text/javascript" {
					isJSType = true
				}
				if strings.ToLower(attr.Key) == "src" {
					jsURL = attr.Val
				}
			}
			if isJSType || strings.HasSuffix(jsURL, ".js") {
				log.Debugf("linked JS in HTML for: %s", urlInput.Host)
				// convert URL to a correct, absolute URL
				jsParsedUrl, err := url.Parse(jsURL)
				if err != nil {
					log.Debugf("Could not parse URL for linked JS: %s, %s", urlInput.Host, jsURL)
					return
				}
				// We need to resolve the JS URL correctly.
				// Remember that we saved the URL of our last request in lastRequestURL?
				// Note the ResolveReference will return the JS URL if it is absolute;
				// otherwise it will correctly interpret the path. Go, Go devs!

				if jsParsedUrl == nil {
					log.Fatalf("Whoa! jsParsedUrl is nil. lastRequest was: %s", lastRequestURL.String())
				}
				if baseHref != "" {
					baseURL, err := url.Parse(baseHref)
					if err != nil {
						log.Warningf("Could not create correct URL from base tag URL provided: %s, %s", urlInput.Host, baseHref)
						return
					}
					jsParsedUrl = baseURL.ResolveReference(jsParsedUrl)
				} else {
					jsParsedUrl = lastRequestURL.ResolveReference(jsParsedUrl)
				}

				// Some fix-ups are still necessary
				if jsParsedUrl.Scheme == "" {
					jsParsedUrl.Scheme = lastRequestURL.Scheme
				}

				// Add to cache and create a URLInput. In each scan, we try to fetch a URL once only,
				// i.e. by adding it to the cache here (before we even know whether it is reachable),
				// we guarantee that no further goroutine will even try to fetch it.

				_, inCache := m.jsURLCache.peek(jsParsedUrl.String())

				if !inCache {
					log.Debugf("Created new JS job for %s: %s", urlInput.Host, jsParsedUrl.String())
					// we create a new job, but note that host, IP, and scheme refer to our original
					// urlInput - due to redirects, FullURL may point somewhere completely different
					// already.
					m.jsJobsChannel <- URLInput{
						FullURL: 	jsParsedUrl.String(),
						Host: 	  	urlInput.Host,
						Scheme:   	urlInput.Scheme,
						Type:    	JSFileType,
					}
					log.Debugf("Sent job for %s, %s", urlInput.Host, jsParsedUrl.String())
				} else {
					// create a result if the URL has been successfully fetched before
					log.Debugf("JS URL already in cache and evaluated: %s", jsParsedUrl.String())
					//res := URLResult{
					//	Host:        urlInput.Host,
					//	InputType:   urlInput.Type,
					//	Hitlist:     "CACHED_RESULT",
					//	LastRequest: lastRequestURL.String(),
					//	Msg:         confirmedStatus,
					//	Page:        nil,
					//	Scheme:      urlInput.Scheme,
					//	StatusCode:  "",
					//	Success:     true,
					//	Timestamp:   time.Now().Unix(),
					//}
					// log.Infof(LogResultToString(true, confirmedStatus), urlInput.Host, urlInput.FullURL)
					// m.resultWriterChannel <- &res
					// There is no need to send to AMQP: it has been processed before.
				}
			}
		}
		// DFS
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	// log.Debugf("Traversing HTML of %s - %s", urlInput.Host, urlInput.FullURL)
	traverse(root)
	// log.Debugf("HTML traversal done for %s - %s", urlInput.Host, urlInput.FullURL)
	return
}


func (m *MinerScanner) interceptRedirect(req *http.Request, viaRequests []*http.Request) error {

	if strings.HasPrefix(req.URL.Host, "127.") || req.URL.Host == "::1" || req.URL.Host == "localhost" {
		referer := req.Header.Get("Referer")
		log.Warningf("Redirect to localhost with referer: ", referer)
		return errors.New("REDIRECT_TO_LOCALHOST")
	}

	if strings.Trim(req.URL.Host, m.ldhSet) != "" {
		log.Warningf("Request using non-Punycode domain: ", req.URL.Host)
		return errors.New("Non-Punycode domain.")
	}

	log.Debugf("REDIRECTURL: %s", req.URL)
	if len(viaRequests) > m.config.MaxRedirects {
		return errors.New("TOO_MANY_REDIRECTS.")
	}
	return nil
}








// Create regexes from strings
func createRegexesFromStrings(stringList []string) []*regexp.Regexp {

	var regexList []*regexp.Regexp

	for _, regex := range stringList {
		compiledRegex, err := regexp.Compile(regex)
		if err != nil {
			fmt.Errorf("invalid regular expression in input list: %s - %s", regex, err)
			log.Fatalf("invalid regular expression in input list: %s - %s", regex, err)
		}
		regexList = append(regexList, compiledRegex)
	}

	return regexList
}


// Return at most the first 50 bytes of a string
func extractFirst50Bytes(s string) string {

	if len(s) < 50 {
		return s
	} else {
		return s[0:49]
	}

}
