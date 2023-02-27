package models

import (
	"bytes"
	"fmt"
	"io"
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

// Returns the list of MD5s of files for the key URL
func QueryPivotLDB(key string) []string {
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
func QueryCryptoLDB(key string) []CryptoItem {
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
func GetCryptoByURL(md5Url string) []CryptoItem {
	var ret []CryptoItem
	res := QueryPivotLDB(md5Url)

	algorithms := make(map[string]CryptoItem)
	for r := range res {
		_ = r
		resCr := QueryCryptoLDB(res[r])
		for r2 := range resCr {
			if v, exist := algorithms[resCr[r2].Algorithm]; !exist {
				algorithms[resCr[r2].Algorithm] = CryptoItem{Algorithm: resCr[r2].Algorithm, Strenght: resCr[r2].Strenght, Usage: 1}
			} else {
				v.Usage++
				algorithms[resCr[r2].Algorithm] = v
			}
		}
	}
	for _, v := range algorithms {
		item := CryptoItem{Algorithm: v.Algorithm, Strenght: v.Strenght, Usage: v.Usage}
		ret = append(ret, item)
	}
	return ret
}
