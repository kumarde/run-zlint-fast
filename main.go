package main

import (
	"encoding/base64"
	"encoding/csv"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2"
	"github.com/zmap/zlint/v2/lint"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ( // flags
	listLintsJSON   bool
	listLintSources bool
	prettyprint     bool
	format          string
	nameFilter      string
	includeNames    string
	excludeNames    string
	includeSources  string
	excludeSources  string
	dataDir         string

	// version is replaced by GoReleaser using an LDFlags option at release time.
	version = "dev"
)

func msToTime(ms string) (time.Time, error) {
	msInt, err := strconv.ParseInt(ms, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(0, msInt*int64(time.Millisecond)), nil
}

func init() {
	flag.StringVar(&dataDir, "data-dir", "/data2/nsrg/ct/deduped_certs_2020-01-01/", "Data directory")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZLint version %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] file...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetLevel(log.InfoLevel)
}

func worker(in <-chan []string, wg *sync.WaitGroup) {
	defer wg.Done()
	for line := range in {
		earliestCT := line[5]
		t, err := msToTime(earliestCT)
		if err != nil {
			log.Fatal("could not parse timestamp")
		}
		if t.Year() == 2019 {
			doLint(line[1])
		}
	}
}

func reader(files []os.FileInfo, dataDir string, out chan<- []string, wg *sync.WaitGroup) {
	defer wg.Done()
	for _, file := range files {

		filePath := filepath.Join(dataDir, file.Name())
		inFile, err := os.Open(filePath)
		if err != nil {
			log.Fatal("could not open filename: ", err)
		}

		csvReader := csv.NewReader(inFile)
		records, err := csvReader.ReadAll()
		if err != nil {
			log.Error("could not parse CSV: ", err)
		}
		for _, line := range records {
			out <- line
		}
		inFile.Close()
	}
}

func main() {
	files, err := ioutil.ReadDir(dataDir)
	if err != nil {
		log.Fatal(err)
	}

	lineChannel := make(chan []string, 1000000)
	readerWg := sync.WaitGroup{}
	workerWg := sync.WaitGroup{}
	readerWg.Add(1)
	go reader(files, dataDir, lineChannel, &readerWg)

	for i := 0; i < runtime.NumCPU(); i++ {
		workerWg.Add(1)
		go worker(lineChannel, &workerWg)
	}
	readerWg.Wait()
	close(lineChannel)
	workerWg.Wait()
}

func doLint(certString string) {
	asn1Data, err := base64.StdEncoding.DecodeString(certString)
	if err != nil {
		log.Fatal("unable to parse base64: %s", err)
	}
	c, err := x509.ParseCertificate(asn1Data)
	zlintResult := zlint.LintCertificate(c)
	fmt.Println(zlintResult.ErrorsPresent)
}

// trimmedList takes a comma separated string argument in raw, splits it by
// comma, and returns a list of the separated elements after trimming spaces
// from each element.
func trimmedList(raw string) []string {
	var list []string
	for _, item := range strings.Split(raw, ",") {
		list = append(list, strings.TrimSpace(item))
	}
	return list
}

// setLints returns a filtered registry to use based on the nameFilter,
// includeNames, excludeNames, includeSources, and excludeSources flag values in
// use.
func setLints() (lint.Registry, error) {
	// If there's no filter options set, use the global registry as-is
	if nameFilter == "" && includeNames == "" && excludeNames == "" && includeSources == "" && excludeSources == "" {
		return lint.GlobalRegistry(), nil
	}

	filterOpts := lint.FilterOptions{}
	if nameFilter != "" {
		r, err := regexp.Compile(nameFilter)
		if err != nil {
			return nil, fmt.Errorf("bad -nameFilter: %v", err)
		}
		filterOpts.NameFilter = r
	}
	if excludeSources != "" {
		if err := filterOpts.ExcludeSources.FromString(excludeSources); err != nil {
			log.Fatalf("invalid -excludeSources: %v", err)
		}
	}
	if includeSources != "" {
		if err := filterOpts.IncludeSources.FromString(includeSources); err != nil {
			log.Fatalf("invalid -includeSources: %v\n", err)
		}
	}
	if excludeNames != "" {
		filterOpts.ExcludeNames = trimmedList(excludeNames)
	}
	if includeNames != "" {
		filterOpts.IncludeNames = trimmedList(includeNames)
	}

	return lint.GlobalRegistry().Filter(filterOpts)
}
