package models

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type CryptoItem struct {
	Algorithm string
	Strenght  string
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
type PivotItem struct {
	UrlHash  string
	FileHash string
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

func QueryBulkPivotLDB(keys []string) map[string][]string {
	ret := make(map[string][]string)

	f, err := os.Create("pivot.txt")
	if err != nil {
		return map[string][]string{}
	}
	for job := range keys {
		if keys[job] != "" {
			line := fmt.Sprintf("select from oss/pivot key %s csv hex 32\n", keys[job])
			f.WriteString(line)
		}
	}
	f.Close()

	ldbCmd := exec.Command("./ldb", "-f", "pivot.txt")
	buffer, _ := ldbCmd.Output()

	//split results line by line
	//each row contains 3 values: <UrlMD5>,<FileMD5>,unknown
	lines := strings.Split(string(buffer), "\n")

	for i := range lines {
		fields := strings.Split(lines[i], ",")
		if len(fields) == 3 {
			ret[fields[0]] = append(ret[fields[0]], fields[1])
		}
	}
	//os.Remove("pivot.txt")
	return ret
}

func QueryBulkCryptoLDB(items map[string][]string) map[string][]CryptoItem {
	algorithms := make(map[string][]CryptoItem)

	f, err := os.OpenFile("crypto.txt", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return map[string][]CryptoItem{}
	}
	added := make(map[string]bool)
	for job := range items {
		fileHashes := items[job]
		for r := range fileHashes {
			if _, exist := added[fileHashes[r]]; !exist {
				line := fmt.Sprintf("select from quique/crypto key %s csv hex 16\n", fileHashes[r])
				f.WriteString(line)
				added[fileHashes[r]] = true
			}
		}
	}
	f.Close()

	ldbCmd := exec.Command("./ldb", "-f", "crypto.txt")
	buffer, _ := ldbCmd.Output()
	lines := strings.Split(string(buffer), "\n")
	for i := range lines {
		fields := strings.Split(lines[i], ",")
		if len(fields) == 3 {
			algorithm := CryptoItem{Algorithm: fields[1], Strenght: fields[2]}
			algorithms[fields[0]] = append(algorithms[fields[0]], algorithm)
		}
	}
	//os.Remove("crypto.txt")
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
