package models

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type CryptoItem struct {
	Algorithm string
	Strenght  string
	Usage     int32
}
type CryptoResult struct {
	Crypto  []CryptoItem
	Purl    string
	Version string
}

type UrlItem struct {
	UrlHash  string
	PurlName string
	Version  string
}

// Checks if the LBD exists and returns the list of available tables
func PingLDB(ldbname string) ([]string, error) {
	var ret []string
	entry, err := os.ReadDir("/var/lib/ldb/" + ldbname)
	if err != nil {
		return []string{}, errors.New("Problems opening LDB " + ldbname)
	}
	for e := range entry {
		if entry[e].IsDir() {
			ret = append(ret, entry[e].Name())
		}
	}

	return ret, nil
}

// Single item worker for Cryptography. From a MD5 of a file enqueues a list of CryptoItem
func cryptoWorker(id int, jobs <-chan string, resultsChan chan<- []CryptoItem) {

	for jo := range jobs {
		aux := queryCryptoLDB(jo)
		resultsChan <- aux
	}
}

// Get Cryptographic usage from a URL encoded in MD5
func GetCryptoByURL(md5Url string) []CryptoItem {
	var ret []CryptoItem
	res := queryPivotLDB(md5Url)
	jobs := make(chan string)
	results := make(chan []CryptoItem, len(res))

	for w := 1; w <= 5; w++ {
		go cryptoWorker(w, jobs, results)
	}

	for job := range res {
		jobs <- res[job]
	}

	algorithms := make(map[string]CryptoItem)
	for a := 1; a <= len(res); a++ {
		result := <-results
		for r2 := range result {
			if v, exist := algorithms[result[r2].Algorithm]; !exist {
				algorithms[result[r2].Algorithm] = CryptoItem{Algorithm: result[r2].Algorithm, Strenght: result[r2].Strenght, Usage: 1}
			} else {
				v.Usage++
				algorithms[result[r2].Algorithm] = v
			}
		}
	}
	for _, v := range algorithms {
		item := CryptoItem{Algorithm: v.Algorithm, Strenght: v.Strenght, Usage: v.Usage}
		ret = append(ret, item)
	}
	return ret
}

// Returns the list of MD5s of files for the key URL
func queryPivotLDB(key string) []string {
	ldb := fmt.Sprintf("select from oss/pivot key %s csv hex 32", key)
	var files []string
	echoCmd := exec.Command("echo", ldb)
	ldbCmd := exec.Command("ldb")
	reader, writer := io.Pipe()
	var buf bytes.Buffer

	//set the output of "echo" command to pipe writer
	//set the input of the "ldb" command pipe reader
	echoCmd.Stdout = writer
	ldbCmd.Stdin = reader

	//cache the output of "ldb" to memory
	ldbCmd.Stdout = &buf

	//start executions
	echoCmd.Start()
	ldbCmd.Start()

	//waiting for "echo" command complete and close the writer
	echoCmd.Wait()
	writer.Close()

	//waiting for the "ldb" command complete and close the reader
	ldbCmd.Wait()
	reader.Close()

	//split results line by line
	//each row contains 2 values: <UrlMD5>,<FileMD5>
	lines := strings.Split(buf.String(), "\n")
	//fmt.Println(lines)
	for i := range lines {
		fields := strings.Split(lines[i], ",")
		if len(fields) == 3 {
			files = append(files, fields[1])
		}
	}

	return files

}

// Returns the list of Cryptographic algorithms used in the <Key> file
func queryCryptoLDB(key string) []CryptoItem {
	ldb := fmt.Sprintf("select from oss/cryptography key %s csv hex 16", key)

	echoCmd := exec.Command("echo", ldb)
	ldbCmd := exec.Command("ldb_enc")

	reader, writer := io.Pipe()
	var buf bytes.Buffer

	//set the output of "echo" command to pipe writer
	//set the input of the "ldb" command pipe reader
	echoCmd.Stdout = writer
	ldbCmd.Stdin = reader

	//cache the output of "ldb" to memory
	ldbCmd.Stdout = &buf

	//start executions
	echoCmd.Start()
	ldbCmd.Start()

	//waiting for "echo" command complete and close the writer
	echoCmd.Wait()
	writer.Close()

	//waiting for the "ldb" command complete and close the reader
	ldbCmd.Wait()
	reader.Close()

	//split results line by line
	//each row contains 3 values: <FileMD5>,<AlgorithmName>,<Strength>
	lines := strings.Split(buf.String(), "\n")
	var algorithms []CryptoItem

	for i := range lines {
		fields := strings.Split(lines[i], ",")
		if len(fields) == 3 {
			algorithm := CryptoItem{Algorithm: fields[1], Strenght: fields[2]}
			algorithms = append(algorithms, algorithm)
		}
	}
	return algorithms
}

func ContainsTable(arr []string, value string) bool {
	for r := range arr {
		if arr[r] == value {
			return true
		}
	}
	return false

}
