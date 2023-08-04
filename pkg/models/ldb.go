package models

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/google/uuid"
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

var LDBCryptoTableName string
var LDBPivotTableName string
var LDBBinPath string

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

func QueryBulkPivotLDB(keys []string) (map[string][]string, error) {
	ret := make(map[string][]string)
	name := fmt.Sprintf("/tmp/%s-pivot.txt", uuid.New().String())
	f, err := os.Create(name)
	if err != nil {
		return map[string][]string{}, err
	}
	for job := range keys {
		if keys[job] != "" {
			line := fmt.Sprintf("select from %s key %s csv hex 32\n", LDBPivotTableName, keys[job])
			f.WriteString(line)
		}
	}
	f.Close()
	_, err = os.Stat(LDBBinPath)
	if os.IsNotExist(err) {

		return map[string][]string{}, errors.New("LDB console not found")
	}

	ldbCmd := exec.Command(LDBBinPath, "-f", name)

	buffer, errLDB := ldbCmd.Output()
	fmt.Println(errLDB)

	//split results line by line
	//each row contains 3 values: <UrlMD5>,<FileMD5>,unknown
	lines := strings.Split(string(buffer), "\n")

	for i := range lines {
		fields := strings.Split(lines[i], ",")
		if len(fields) == 3 {
			ret[fields[0]] = append(ret[fields[0]], fields[1])
		}
	}
	os.Remove(name)
	return ret, nil
}

func QueryBulkCryptoLDB(items map[string][]string) map[string][]CryptoItem {
	algorithms := make(map[string][]CryptoItem)
	name := fmt.Sprintf("/tmp/%s-crypto.txt", uuid.New().String())
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return map[string][]CryptoItem{}
	}
	added := make(map[string]bool)
	for job := range items {
		fileHashes := items[job]
		for r := range fileHashes {
			if _, exist := added[fileHashes[r]]; !exist {
				line := fmt.Sprintf("select from %s key %s csv hex 16\n", LDBCryptoTableName, fileHashes[r])
				f.WriteString(line)
				added[fileHashes[r]] = true
			}
		}
	}
	f.Close()

	ldbCmd := exec.Command(LDBBinPath, "-f", name)
	buffer, _ := ldbCmd.Output()
	lines := strings.Split(string(buffer), "\n")
	for i := range lines {
		fields := strings.Split(lines[i], ",")
		if len(fields) == 3 {
			algorithm := CryptoItem{Algorithm: fields[1], Strenght: fields[2]}
			algorithms[fields[0]] = append(algorithms[fields[0]], algorithm)
		}
	}
	//os.Remove(name)
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
