package scanner

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"compress/gzip"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"crypto/sha1"
)


type ResultWriter struct {
	csvWriter 		*csv.Writer
	dataDir 		string
	dumpPages 		bool
	inputChannel 	chan *URLResult
	outputFile 		*os.File
}


func NewResultWriter(inputChan chan *URLResult, dataDir string, dumpPages bool, outFile string) *ResultWriter {

	outputFile, err := os.Create(outFile)

	if err != nil {
		fmt.Errorf("could not create output file: %s", err)
		log.Fatalf("could not create output file: ", err)
	}

	resultWriter := ResultWriter{
		csvWriter: csv.NewWriter(outputFile),
		dataDir: dataDir,
		dumpPages: dumpPages,
		inputChannel: inputChan,
		outputFile: outputFile,
	}

	// try to create the data dir if it does not exist
	if dumpPages {
		if _, err := os.Stat(dataDir); err != nil {
			if err := os.Mkdir(dataDir,0770); err != nil {
				log.Fatalf("Could not create data dir: ", err)
			}
		}
	}

	return &resultWriter

}


func (r *ResultWriter) ProcessResults(scanWg *sync.WaitGroup) {
	defer func() {
		r.outputFile.Close()
		scanWg.Done()
	}()

	var pageWritingGroup sync.WaitGroup

	for result := range r.inputChannel {
		log.Debugf("Receiving result to write out for %s", result.Host)
		record := result.toRecord()
		err := r.csvWriter.Write(record)
		if err != nil {
			log.Fatalf("Failed to write to output file.")
		}
		r.csvWriter.Flush()
		if result.Page == nil {
			log.Warningf("Nil page in result for ", result.Host)
		}
		// if there is a page in the result, we gzip and write to file
		if r.dumpPages && result.Page != nil {
			filename := ""
			// Need to write to unique file names for JS
			// Add result type ("obfuscated" or "mining-keywords") for linked JS.
			// Hash fullURL for these files - cache guarantees we won't try to overwrite.
			resultType := ResultToString(result.Msg)
			if result.InputType == WebRootType {
				filename = filename + result.Host + "_" + resultType + "_" + strconv.FormatInt(time.Now().Unix(), 10) + ".gz"
				sha1OfFilename := sha1.Sum([]byte(filename))
				sha1OfFilenameHex := hex.EncodeToString(sha1OfFilename[:])
				// we take the first three hex characters to create sub-dirs
				subDir := path.Join(r.dataDir, sha1OfFilenameHex[:3])
				if _, err := os.Stat(subDir); err != nil {
					if err := os.Mkdir(subDir,0770); err != nil {
					log.Fatalf("Could not create sub dir: ", err)
					}
				}
				filename = path.Join(subDir, filename)
				log.Infof("HITLIST WEBROOT Domain: %s Hitlist: %s", result.Host, result.Hitlist)

			} else if result.InputType == JSFileType {
				sha1Sum := sha1.Sum([]byte(result.FullURL))
				sha1SumBase64 := hex.EncodeToString(sha1Sum[:])
				filename = filename + result.Host + "_" + resultType + "_" + sha1SumBase64 + "_" + strconv.FormatInt(time.Now().Unix(), 10) + ".gz"
				sha1OfFilename := sha1.Sum([]byte(filename))
				sha1OfFilenameHex := hex.EncodeToString(sha1OfFilename[:])
				// we take the first three hex characters to create sub-dirs
				subDir := path.Join(r.dataDir, sha1OfFilenameHex[:3])
				if _, err := os.Stat(subDir); err != nil {
					if err := os.Mkdir(subDir,0770); err != nil {
					log.Fatalf("Could not create sub dir: ", err)
					}
				}
				filename = path.Join(subDir, filename)
				log.Infof("HITLIST LINKED JS Domain: %s Hitlist: %s", result.Host, result.Hitlist)

			} else {
				log.Fatalf("Cannot write JS result file: unknown urlInput.Type")
			}

			log.Debugf("Writing localResult for %s to %s", result.Host, filename)
			if _, err = os.Stat(filename); err == nil {
				log.Warningf("Page dump already exists: ", filename)
				filename = strings.TrimSuffix(filename, path.Ext(filename)) + "_dup" + ".gz"
			}
			gzipFile, err := os.Create(filename)
			if err != nil {
				log.Fatalf("Could not write gzipped page dump: ", filename)
			}
			gzipWriter := gzip.NewWriter(gzipFile)
			localPage := result.Page
			if _, err = gzipWriter.Write(*localPage); err != nil {
				log.Fatalf("Could not write gzipped page dump: ", filename)
			}
			gzipWriter.Close()
			gzipFile.Close()
			log.Debugf("Wrote localResult for %s to %s", result.Host, filename)
		}
	}

	msg := "finished writing to output file"
	fmt.Println(msg)
	log.Infof(msg)
	pageWritingGroup.Wait()
}
