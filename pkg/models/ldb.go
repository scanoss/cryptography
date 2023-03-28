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

func GetCryptoByURL(md5Url string) []CryptoItem {

	ret := queryCLCryptoLDB(md5Url)
	return ret
}

// Returns the list of MD5s of files for the key URL
func queryCLCryptoLDB(key string) []CryptoItem {
	ldb := fmt.Sprintf("select from oss/cryptocomponent key %s csv hex 16", key)
	var res []CryptoItem
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
	for i := range lines {
		fields := strings.Split(lines[i], ",")
		if len(fields) == 3 {
			item := CryptoItem{Algorithm: fields[1], Strenght: fields[2]}

			res = append(res, item)
		}
	}

	return res

}

func ContainsTable(arr []string, value string) bool {
	for r := range arr {
		if arr[r] == value {
			return true
		}
	}
	return false

}
