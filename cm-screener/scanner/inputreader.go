package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"net/url"

	log "github.com/sirupsen/logrus"
)

type InputReader struct {
	https 				bool
	inputFile 			*os.File
	outputChannel	 	chan URLInput
}




func NewInputReader(outputChan chan URLInput, https bool, inputFilename string) *InputReader {

	inputFile, err := os.Open(inputFilename)

	if err != nil {
		fmt.Errorf("could not open input file with URLs: %s", err)
		log.Fatalf("could not open input file with URLs: ", err)
	}

	inputReader := InputReader {
		https: https,
		inputFile: inputFile,
		outputChannel: outputChan,
	}

	return &inputReader

}



func (r *InputReader) Parse(scanWg *sync.WaitGroup) {

	defer func() {
		r.inputFile.Close()
		close(r.outputChannel)
		scanWg.Done()
	}()

	scanner := bufio.NewScanner(r.inputFile)

	var input URLInput

	for scanner.Scan() {
		line := scanner.Text()
		// line is a comment, skip
		if strings.HasPrefix(line, "#") {
			continue
		}
		lineParts := strings.Split(line, ",")

		if len(lineParts) > 2 {
			log.Fatalf("Invalid format of input file: ", line)
		}

		if len(lineParts) == 2 {
			if _, err := strconv.Atoi(lineParts[0]); err != nil {
				log.Fatalf("Invalid data type in input file: ", line)
			}
		}

		// test if we are dealing with a correct URL
		var scheme string
		if r.https {
			scheme = "https://"
		} else {
			scheme = "http://"
		}

		var host string
		if len(lineParts) == 1 {
			host = lineParts[0]
		} else {
			host = lineParts[1]
		}

		rawUrl := scheme + "://" + host

		_, err := url.Parse(rawUrl)
		if err != nil {
			log.Errorf("Unparseable URL: ", rawUrl)
			continue
		}

		input = URLInput {
			Host: host,
			Type: WebRootType,
			Scheme: scheme,
		}

		log.Debugf("Sending input to scanner module: %s", input.Host)
		r.outputChannel <- input
	}

}
