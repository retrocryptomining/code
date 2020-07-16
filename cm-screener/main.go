package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	_ "net/http/pprof"
	// "github.com/pkg/profile"

	"bitbucket.org/ralphholz_usyd/cm-scanner/scanner"
	"net/http"
	"runtime"
)



var opts struct {
	AMQPCapacity 			int 		`long:"amqpcapacity" description:"Number of results buffered by UseAMQP forwarder (defaults to level of concurrency)"`
	AMQPURL 				string 		`long:"amqpurl" description:"URL to UseAMQP (with user, password, port). This switches on UseAMQP."`
	CacheSize 				int 		`long:"cachesize" description:"Number of JS URLs to hold in cache. Higher number speeds up scan, but costs RAM." default:"100000" value-name:"CACHESIZE"`
	Concurrency         	int         `short:"c" long:"concurrency" description:"Number of concurrent requests to domains" default:"100"`
	DataDir 				string      `short:"d" long:"datadir" description:"Location where to write page dumps. Defaults to local working directory."`
	Debug 					bool 		`long:"debug" description:"Enable debug mode."`
	DumpPages				bool 		`long:"dumppages" description:"Switches on page dumps of candidate pages."`
	ExchangeDataDir 		string		`long:"exchangedatadir" description:"If cm-detector is running on the same machine, use this as a faster way to exchange page dumps (bypasses AMQP for page transfers)."`
	FollowJSLinks 			bool 		`short:"f" long:"followjs" description:"Follow links to JS files (instead of working on inline JS only)"`
	Https 					bool 		`long:"https" description:"Use HTTPS"`
	InputFile           	string 		`short:"i" long:"inputfile" description:"input file" default:"input.csv"`
	LogFile             	string 		`short:"l" long:"logfile" description:"Log to LOGFILE (absolute path). Default is a timestamped log file name." value-name:"LOG-FILE" default:"cm-scanner.log"`
	LogLevel                string  	`long:"loglevel" description:"Log level (allowed: info, warning, debug, error, fatal, panic; default: info)" ini-name:"LogLevel"`
	MaxRedirect             int    		`long:"maxredirect" description:"How many redirects to follow" value-name:"MAX-REDIRECT" default:"1"`
	MiningFilenamesFile     string 		`long:"miningfilenames" description:"file containing typical mining JS filenames" value-name:"MINING-JSFILE" default:"mining-js-filenames.txt"`
	MiningKeywordsFile      string 		`long:"miningkeywords" description:"file with keywords used in mining JS" value-name:"MINING-KEYWORDS-FILE"`
	MiningURLPatternsFile   string 		`long:"miningurlpatterns" description:"file with WSS URL patterns used in mining JS" value-name:"MINING-URLPATTERNS" default:"mining-js-wsurlpatterns.txt"`
	ObfuscationKeywordsFile string 		`long:"obfuscationkeywords" description:"file with patterns identifying typical obfuscation attempts" value-name:"OBFUSCATION-KEYWORDS-FILE"`
	OutputFile              string 		`short:"o" long:"outputfile" description:"Name of output file" default:"output.csv"`
	Profile                 bool   		`long:"profile" description:"Switch on profiling via webserver"`
	ScanID                  string 		`long:"scanid" description:"Type of scan (freely chosen)" default:"default" value-name:"SCANID"`
	Timeout                 int    		`short:"t" long:"timeout" description:"Timeout to wait for reply (in seconds)" default:"30"`
	UserAgent               string 		`long:"useragent" description:"User agent to send (default: a Chrome/macOS header)"`
}

var VersionString = "unset"

func main() {

	fmt.Println(VersionString)

	if len(os.Args) == 1 {
		fmt.Println("This is cm-scanner. Use --help to print help.")
		os.Exit(0)
	}

	if _, err := flags.Parse(&opts); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	defaultUserAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"
	if opts.UserAgent == "" {
		opts.UserAgent = defaultUserAgent
	}

	// Initialize Logging.
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = time.StampMicro
	customFormatter.FullTimestamp = true
	customFormatter.DisableColors = true
	log.SetFormatter(customFormatter)

	defaultLogLevel := "info"
	if opts.LogLevel == "" {
		opts.LogLevel = defaultLogLevel
	}
	if opts.Debug {
		opts.LogLevel = "debug"
	}
	logLevel, levelErr := log.ParseLevel(opts.LogLevel)
	if levelErr != nil {
		log.Fatalf("Could not parse log level: ", levelErr)
	}
	log.SetLevel(logLevel)
	log.Infof("Loglevel: %s", opts.LogLevel)

	f, err := os.OpenFile(opts.LogFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
	if err != nil {
		fmt.Println("error opening logfile: ", err)
		os.Exit(1)
	}
	defer f.Close()
	log.SetOutput(f)

	jsConcurrency := int(float64(opts.Concurrency) * 0.3)
	webrootConcurrency := int(float64(opts.Concurrency) * 0.7)

	// get UseAMQP options
	useAMQP := false
	if opts.AMQPURL != "" {
		useAMQP = true
		if opts.AMQPCapacity == 0 {
			opts.AMQPCapacity = opts.Concurrency
		}
	}

	// Create the channels
	inputreaderToScannerChan := make(chan scanner.URLInput, webrootConcurrency)
	scannerToResultwriterChan := make(chan *scanner.URLResult, opts.Concurrency)
	scannerToResultForwarderChan := make(chan *scanner.URLResult, opts.Concurrency)

	// Create the input reader
	inputReader := scanner.NewInputReader(inputreaderToScannerChan, opts.Https, opts.InputFile)

	// Create the scanner
	// We always do: test for JS filenames, test for URL patterns
	miningFilenameStrings := buildRegexStringsFromFile(opts.MiningFilenamesFile)
	miningURLPatternsString := buildRegexStringsFromFile(opts.MiningURLPatternsFile)


	msc := scanner.MinerScannerConfig{
		CacheSize:               	opts.CacheSize,
		DoMiningKeywords:        	false,
		DoObfuscation:           	false,
		DumpPages:               	opts.DumpPages,
		FollowJSLinks:           	false,
		JSConcurrency:           	jsConcurrency,
		MaxRedirects:            	opts.MaxRedirect,
		MiningJSFilenameStrings: 	miningFilenameStrings,
		MiningURLPatternsStrings: 	miningURLPatternsString,
		Timeout:                 	opts.Timeout,
		UseAMQP:                 	useAMQP,
		UserAgent:               	opts.UserAgent,
		WebrootConcurrency:      	webrootConcurrency,
	}

	if opts.MiningKeywordsFile != "" {
		msc.MiningKeywordsStrings = buildRegexStringsFromFile(opts.MiningKeywordsFile)
		msc.DoMiningKeywords = true
	}


	if opts.ObfuscationKeywordsFile != "" {
		msc.ObfuscationStrings = buildRegexStringsFromFile(opts.ObfuscationKeywordsFile)
		msc.DoObfuscation = true
	}

	if opts.FollowJSLinks {
		msc.FollowJSLinks = true
	}

	minerScanner := scanner.NewMinerScanner(inputreaderToScannerChan, scannerToResultForwarderChan, scannerToResultwriterChan, &msc)

	// Create the result writer
	resultWriter := scanner.NewResultWriter(scannerToResultwriterChan, opts.DataDir, opts.DumpPages, opts.OutputFile)

	// Create the result forwarder
	var resultForwarder *scanner.ResultForwarder
	if useAMQP {
		if opts.ExchangeDataDir != "" {
			resultForwarder = scanner.NewResultForwarder(scannerToResultForwarderChan, opts.AMQPCapacity, opts.AMQPURL, opts.ExchangeDataDir, opts.ScanID)

		} else {
			resultForwarder = scanner.NewResultForwarder(scannerToResultForwarderChan, opts.AMQPCapacity, opts.AMQPURL, "", opts.ScanID)
		}
	}

	var scanWg sync.WaitGroup

	if useAMQP {
		scanWg.Add(4)
	} else {
		scanWg.Add(3)
	}


	log.Infof("Git revision: " + VersionString)
	for _, s := range optsToString(&msc) {
		log.Infof(s)
	}

	fmt.Println("Firing up...")
	log.Infof("STARTTIME: %s", strconv.FormatInt(time.Now().Unix(), 10))

	// start result writer
	go resultWriter.ProcessResults(&scanWg)

	// start result forwarder
	if useAMQP {
		go resultForwarder.ProcessResults(&scanWg)
	}

	// start scanner
	go minerScanner.Scan(&scanWg)

	// start input reader
	go inputReader.Parse(&scanWg)


	if opts.Profile {
		//p := profile.Start(profile.MemProfile, profile.ProfilePath("."))
		// defer p.Stop()
		runtime.SetBlockProfileRate(10)
		go func() {
			http.ListenAndServe("localhost:4280",nil)
		}()
	}

	scanWg.Wait()
	fmt.Println("Winding down...")
	log.Infof("ENDTIME: %s", strconv.FormatInt(time.Now().Unix(), 10))

}



func buildRegexStringsFromFile(filename string) []string {
	var retStrings []string

	fileIn, err := os.Open(filename)

	if err != nil {
		fmt.Errorf("could not read regex list: %s", err)
		log.Fatalf("Could not read regex list: ", err)
	}

	defer fileIn.Close()

	s:= bufio.NewScanner(fileIn)
	// scanner.Split(bufio.ScanLines)

	for s.Scan() {
		line := s.Text()

		if len(line) > 0 && !strings.HasPrefix(line,"#") {
			retStrings = append(retStrings, strings.TrimSuffix(line, "\n"))
		}
	}

	return retStrings
}



func optsToString(msc *scanner.MinerScannerConfig) []string {

	result := []string {
		"CacheSize: " + strconv.Itoa(opts.CacheSize),
		"Concurrency: " + strconv.Itoa(opts.Concurrency),
		"DataDir: " + opts.DataDir,
		"Debug: " + strconv.FormatBool(opts.Debug),
		"DoMiningKeywords: " + strconv.FormatBool(msc.DoMiningKeywords),
		"DoObfuscation: " + strconv.FormatBool(msc.DoObfuscation),
		"DumpPages: " + strconv.FormatBool(opts.DumpPages),
		"FollowJSLinks: " + strconv.FormatBool(opts.FollowJSLinks),
		"HTTPS: " + strconv.FormatBool(opts.Https),
		"Inputfile: " + opts.InputFile,
		"Logfile: " + opts.LogFile,
		"Loglevel: " + opts.LogLevel,
		"MaxRedirect: " + strconv.Itoa(opts.MaxRedirect),
		"MinerFilenamesFile: " + opts.MiningFilenamesFile,
		"MiningKeywordsFile: " + opts.MiningKeywordsFile,
		"MiningURLPatternsFile: " + opts.MiningURLPatternsFile,
		"ObfuscationKeywordsFile: " + opts.ObfuscationKeywordsFile,
		"Outputfile: " + opts.OutputFile,
		"Profile: " + strconv.FormatBool(opts.Profile),
		"ScanID: " + opts.ScanID,
		"Timeout: " + strconv.Itoa(opts.Timeout),
		"UserAgent: " + opts.UserAgent,
	}

	return result
}
