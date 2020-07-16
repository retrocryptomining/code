package scanner

import (
	"github.com/streadway/amqp"
	log "github.com/sirupsen/logrus"
	"sync"
	"strconv"
	"time"
	"crypto/sha1"
	"encoding/hex"
	"compress/zlib"
	"bytes"
	"bufio"
	"path"
	"os"
	"strings"
	"compress/gzip"
)


type ResultForwarder struct {
	amqpChannel    			*amqp.Channel
	detectorExchangeDir 	string
	detectorQueue  			*amqp.Queue
	conn           			*amqp.Connection
	connNotifyChan 			chan *amqp.Error
	inputChannel   			chan *URLResult
	scanID         			string
	validatorQueue 			*amqp.Queue
}


func NewResultForwarder(inputChan chan *URLResult, amqpCapacity int, amqpURL string, detectorExchangeDir string, scanType string) *ResultForwarder {
	conn, err := amqp.Dial(amqpURL)

	if err != nil {
		log.Fatalf("could not connect to AMQP: %s", err)
	}

	// create channel
	amqpChannel, err := conn.Channel()

	if err != nil {
		log.Fatalf("could not create channel to AMQP: %s", err)
	}

	// declare queues
	detectorQueue, err := amqpChannel.QueueDeclare(
		"todetector", // name
		false,   // durable
		false,   // delete when unused
		false,   // exclusive
		false,   // no-wait
		nil,     // arguments
	)

	if err != nil {
		log.Fatalf("could not declare queue %s at AMQP: %s", "todetector", err)
	}

	validatorQueue, err := amqpChannel.QueueDeclare(
		"tovalidator", // name
		false,   // durable
		false,   // delete when unused
		false,   // exclusive
		false,   // no-wait
		nil,     // arguments
	)

	if err != nil {
		log.Fatalf("could not declare queue %s at AMQP: %s", "tovalidator", err)
	}

	fwder := ResultForwarder {
		amqpChannel:   			amqpChannel,
		detectorExchangeDir: 	detectorExchangeDir,
		detectorQueue: 			&detectorQueue,
		conn:          			conn,
		inputChannel:  			inputChan,
		scanID:        			scanType,
		validatorQueue:			&validatorQueue,
	}

	return &fwder

}



func (f *ResultForwarder) ProcessResults(scanWg *sync.WaitGroup) {
	defer func() {
		err := f.conn.Close()
		if err != nil {
			log.Warningf("could not close connection to AMQP; data loss possible: %s", err)
		}
		scanWg.Done()
	}()

	for localResult := range f.inputChannel {
		var correlationID string

		resultType := ResultToString(localResult.Msg)
		if localResult.InputType == WebRootType {
			correlationID = f.scanID + "+" + localResult.Host + "+" + resultType + "+" + strconv.FormatInt(time.Now().Unix(), 10)
		} else if localResult.InputType == JSFileType {
			sha1Sum := sha1.Sum([]byte(localResult.FullURL))
			sha1SumBase64 := hex.EncodeToString(sha1Sum[:])
			correlationID = f.scanID + "+" + localResult.Host + "+" + resultType + "+" + sha1SumBase64 + "+" +  strconv.FormatInt(time.Now().Unix(), 10)
		} else {
			log.Fatalf("cannot process JS result file: unknown urlInput.Type")
		}


		// We send obfuscated results to the cm-detector. If cm-scanner and cm-detector are running on the same machine, we can optionally bypass AMQP for
		// the transfer of these results to the cm-detector - we just tell it where to find them, and store them locally.
		if localResult.Msg == ObfuscatedLinkedJS || localResult.Msg == ObfuscatedInlineJS {

			if f.detectorExchangeDir == "" {

				log.Debugf("sending obfuscated result (page dump) for %s (%s) to cm-detector.", localResult.Host, correlationID)
				var buffer bytes.Buffer
				bufferWriter := bufio.NewWriter(&buffer)
				zipWriter := zlib.NewWriter(bufferWriter)
				if _, err := zipWriter.Write(*localResult.Page); err != nil {
					log.Fatalf("could not write zipped page dump to buffer: ", correlationID)
				}
				zipWriter.Close()
				bufferWriter.Flush()

				err := f.amqpChannel.Publish(
					"", // set exchange to empty
					f.detectorQueue.Name,
					false,
					false,
					amqp.Publishing{
						ContentType:   "application/octet-stream",
						Body:          buffer.Bytes(),
						CorrelationId: correlationID,
					},
				)
				if err != nil {
					log.Fatalf("could not send obfuscated result (page dump) for %s (%s) to cm-detector: %s", localResult.Host, correlationID, err)
				} else {
					log.Debugf("sent obfuscated result (page dump) for %s (%s) to cm-detector.", localResult.Host, correlationID)
				}
			} else {

				correlationID = correlationID + "+LOCALRESULT"

				log.Debugf("sending notification of obfuscated result (local page dump) for %s (%s) to cm-detector.", localResult.Host, correlationID)
				filename := ""
				// Need to write to unique file names for JS
				// Add result type ("obfuscated" or "mining-keywords") for linked JS.
				// Hash fullURL for these files - cache guarantees we won't try to overwrite.
				if localResult.InputType == WebRootType {
					filename = filename + localResult.Host + "_" + resultType + "_" + strconv.FormatInt(time.Now().Unix(), 10) + ".gz"
					sha1OfFilename := sha1.Sum([]byte(filename))
					sha1OfFilenameHex := hex.EncodeToString(sha1OfFilename[:])
					// we take the first three hex characters to create sub-dirs
					subDir := path.Join(f.detectorExchangeDir, sha1OfFilenameHex[:3])
					if _, err := os.Stat(subDir); err != nil {
						if err := os.Mkdir(subDir,0770); err != nil {
						log.Fatalf("Could not create sub dir: ", err)
						}
					}
					filename = path.Join(subDir, filename)
				}  else if localResult.InputType == JSFileType {
					sha1Sum := sha1.Sum([]byte(localResult.FullURL))
					sha1SumBase64 := hex.EncodeToString(sha1Sum[:])
					filename = filename + localResult.Host + "_" + resultType + "_" + sha1SumBase64 + "_" + strconv.FormatInt(time.Now().Unix(), 10) + ".gz"
					sha1OfFilename := sha1.Sum([]byte(filename))
					sha1OfFilenameHex := hex.EncodeToString(sha1OfFilename[:])
					// we take the first three hex characters to create sub-dirs
					subDir := path.Join(f.detectorExchangeDir, sha1OfFilenameHex[:3])
					if _, err := os.Stat(subDir); err != nil {
						if err := os.Mkdir(subDir,0770); err != nil {
						log.Fatalf("Could not create sub dir: ", err)
						}
					}
					filename = path.Join(subDir, filename)

				} else {
					log.Fatalf("Cannot write JS result file: unknown urlInput.Type")
				}

				log.Debugf("Writing local page dump before notifying cm-detector for %s to %s", localResult.Host, filename)
				if _, err := os.Stat(filename); err == nil {
					log.Errorf("Page dump already exists: ", filename)
					filename = strings.TrimSuffix(filename, path.Ext(filename)) + "_dup" + ".gz"
				}
				gzipFile, err := os.Create(filename)
				if err != nil {
					log.Fatalf("Could not write gzipped page dump: ", filename)
				}
				gzipWriter := gzip.NewWriter(gzipFile)
				localPage := localResult.Page
				if _, err = gzipWriter.Write(*localPage); err != nil {
					log.Fatalf("Could not write gzipped page dump: ", filename)
				}
				gzipWriter.Close()
				gzipFile.Close()
				log.Debugf("Wrote local page dump before notifying cm-detector for %s to %s", localResult.Host, filename)

				// now notify cm-detector
				err = f.amqpChannel.Publish(
					"", // set exchange to empty
					f.detectorQueue.Name,
					false,
					false,
					amqp.Publishing{
						ContentType:   "application/octet-stream",
						Body:          []byte(filename),
						CorrelationId: correlationID,
					},
				)
				if err != nil {
					log.Fatalf("could not send notification for obfuscated result (page dump) for %s (%s) to cm-detector: %s", localResult.Host, correlationID, err)
				} else {
					log.Debugf("sent notification for obfuscated result (page dump) for %s (%s) to cm-detector.", localResult.Host, correlationID)
				}

			}

		// We send straight to cm-validator in any of these cases:
		// 1) JS filename or WSS URL hit
		// 2)  Keyword hit (in inline JS)
		// This is independent of whether the hit is in the webroot or a linked JS.
		} else {
			data := f.scanID + "+" + localResult.Host

			log.Debugf("sending result for %s (%s) to cm-validator.", localResult.Host, correlationID)
			err := f.amqpChannel.Publish(
				"", // set exchange to empty
				f.validatorQueue.Name,
				false,
				false,
				amqp.Publishing{
				ContentType:   "application/octet-stream",
				Body:          []byte(data),
				CorrelationId: correlationID,
				},
			)

			if err != nil {
				log.Fatalf("could not send result for %s (%s) to cm-validator: %s", localResult.Host, correlationID, err)
			} else {
				log.Debugf("sent result for %s (%s) to cm-validator.", localResult.Host, correlationID)
			}

		}
	}

	log.Debug("finished writing to AMQP")

}
