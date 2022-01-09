package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Downloader struct {
	coreRulesetArchivePath string
	corazaConfPath         string
	owaspConfExamplePath   string

	config SecRules
}

func NewDownloader(config SecRules) (dl *Downloader) {
	dl = &Downloader{config: config}

	dl.coreRulesetArchivePath = filepath.Join(os.TempDir(), "coreruleset.tar.gz")
	dl.corazaConfPath = filepath.Join(config.DownloadedPath, "coraza.conf")
	dl.owaspConfExamplePath = filepath.Join(config.DownloadedPath, config.OwaspUrlExampleFile)

	return
}

func (dl Downloader) DownloadCorazaRecommendation() error {
	return downloadUrlFile(dl.config.RecommendedUrl, dl.corazaConfPath)
}

func (dl Downloader) DownloadOwaspCoreRules() (string, error) {
	err := downloadUrlFile(dl.config.OwaspUrl, dl.coreRulesetArchivePath)
	if err != nil {
		return "", err
	}
	defer os.Remove(dl.coreRulesetArchivePath)

	// Verify archive SHA1
	if dl.config.OwaspSha != "" {
		err := verifyArchiveSha(dl.coreRulesetArchivePath, dl.config.OwaspSha)
		if err != nil {
			return "", err
		}
	}

	// Opening archive file
	file, err := os.Open(dl.coreRulesetArchivePath)
	if err != nil {
		return "", fmt.Errorf("error while open core ruleset archive at path %s : %s", dl.coreRulesetArchivePath, err.Error())
	}
	archive, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("error while opening a reader for core ruleset archive at path %s : %s", dl.coreRulesetArchivePath, err.Error())
	}

	tr := tar.NewReader(archive)
	return extractRuleFiles(tr, file, dl)
}

func extractRuleFiles(tr *tar.Reader, file *os.File, dl Downloader) (string, error) {
	sourceDir := filepath.Join(dl.config.DownloadedPath, "owasp")
	for {
		archiveFile, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("error trying to get next file in archive %s : %s", file.Name(), err.Error())
		}
		// Select only target files
		if (!strings.Contains(archiveFile.Name, "/rules/") ||
			archiveFile.FileInfo().IsDir()) &&
			archiveFile.FileInfo().Name() != dl.config.OwaspUrlExampleFile {
			continue
		}

		// Checking if owasp folder exist and creating it if needed
		err = os.MkdirAll(sourceDir, 0755)
		if err != nil {
			return "", fmt.Errorf("error while accessing dir %s : %s", sourceDir, err.Error())
		}

		// Creating an empty ruleset file
		filePath := filepath.Join(dl.config.DownloadedPath, "owasp", archiveFile.FileInfo().Name())
		// Special path for OWASP conf example
		if archiveFile.FileInfo().Name() == dl.config.OwaspUrlExampleFile {
			filePath = dl.owaspConfExamplePath
		}
		file, err := os.Create(filePath)
		if err != nil {
			return "", fmt.Errorf("error while creating file at %s : %s", filePath, err.Error())
		}

		// Put content in file
		size, err := io.Copy(file, tr)
		if err != nil {
			return "", fmt.Errorf("error while copying file %s to %s : %s", file.Name(), filePath, err.Error())
		}
		log.Debug().Msgf("Successfully written file %s of %d bytes", file.Name(), size)
		err = file.Close()
		if err != nil {
			return "", fmt.Errorf("error while closing file %s from path %s : %s", file.Name(), filePath, err.Error())
		}
	}
	return sourceDir, nil
}

func verifyArchiveSha(coreRulesetArchivePath, owaspSha string) error {
	hash := sha1.New()
	bytes, _ := os.ReadFile(coreRulesetArchivePath)
	if _, err := hash.Write(bytes); err != nil {
		return fmt.Errorf("error while computing SHA of core ruleset archive : %s", err.Error())
	}
	obtainedSha := hex.EncodeToString(hash.Sum(nil))
	if owaspSha != obtainedSha {
		return fmt.Errorf("expected SHA of core ruleset archive different to obtained value: %s vs %s", owaspSha, obtainedSha)
	}
	log.Info().Msgf("Downloaded archive SHA is valid, obtained %s", obtainedSha)
	return nil
}

/*
Download the file at the target Url to the local path
*/
func downloadUrlFile(targetUrl string, targetPath string) error {
	// Setup http client
	client := http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			r.URL.Opaque = r.URL.Path
			return nil
		},
	}
	// Get data
	resp, err := client.Get(targetUrl)
	if err != nil {
		return fmt.Errorf("error while getting file from url %s : %s", targetUrl, err.Error())
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("received non 200 response code while fetching file from url %s", targetUrl)
	}
	defer resp.Body.Close()

	// Checking if target file directory exist and creating it if needed
	lastSlash := strings.LastIndexByte(targetPath, '/')
	sourceDir := targetPath[0:lastSlash]
	err = os.MkdirAll(sourceDir, 0755)
	if err != nil {
		return fmt.Errorf("error while accessing dir %s : %s", sourceDir, err.Error())
	}

	// Create blank file
	file, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("error while creating file at %s : %s", targetPath, err.Error())
	}
	// Put content on file
	_, err = io.Copy(file, resp.Body)
	defer file.Close()
	if err != nil {
		return fmt.Errorf("error while writing downloaded file %s at %s : %s", targetUrl, targetPath, err.Error())
	}

	log.Info().Msgf("Successfully download %s to %s ", targetUrl, targetPath)
	return nil
}
