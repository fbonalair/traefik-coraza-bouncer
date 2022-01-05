package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"github.com/fbonalair/traefik-coraza-bouncer/configs"
	"github.com/rs/zerolog/log"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var (
	downloadedRulesDir       = configs.Values.SecRules.DownloadedPath
	coreRulesetUrl           = configs.Values.SecRules.OwaspUrl
	corazaConfUrl            = configs.Values.SecRules.RecommendedUrl
	owaspConfExampleFileName = configs.Values.SecRules.OwaspUrlExampleFile
	owaspSha                 = configs.Values.SecRules.OwaspSha

	coreRulesetArchivePath = filepath.Join(os.TempDir(), "coreruleset.tar.gz")
	CorazaConfPath         = filepath.Join(downloadedRulesDir, "coraza.conf")
	OwaspConfExamplePath   = filepath.Join(downloadedRulesDir, owaspConfExampleFileName)
)

func DownloadCorazaRecommendation() bool {
	return downloadUrlFile(corazaConfUrl, CorazaConfPath)
}

func DownloadOwaspCoreRules() bool {
	success := downloadUrlFile(coreRulesetUrl, coreRulesetArchivePath)
	if !success {
		return false
	}
	defer os.Remove(coreRulesetArchivePath)

	// Verify archive SHA1
	if owaspSha != "" {
		hash := sha1.New()
		bytes, _ := os.ReadFile(coreRulesetArchivePath)
		if _, err := hash.Write(bytes); err != nil {
			log.Fatal().Err(err).Msg("Error while computing SHA of core ruleset archive")
		}
		obtainedSha := hex.EncodeToString(hash.Sum(nil))
		if owaspSha != obtainedSha {
			log.Fatal().Msgf("Expected SHA of core ruleset archive different to obtained value: %s vs %s", owaspSha, obtainedSha)
		} else {
			log.Info().Msgf("Downloaded archive SHA is valid, obtained %s", obtainedSha)
		}
	}

	file, err := os.Open(coreRulesetArchivePath)
	if err != nil {
		log.Warn().Err(err).Msgf("Error while open core ruleset archive at path %s", coreRulesetArchivePath)
		return false
	}

	archive, err := gzip.NewReader(file)
	if err != nil {
		log.Warn().Err(err).Msgf("Error while opening a reader for core ruleset archive at path %s", coreRulesetArchivePath)
		return false
	}

	tr := tar.NewReader(archive)
	for {
		archiveFile, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Warn().Err(err).Msgf("Error trying to get next file in archive %s", file.Name())
		}
		// Select only target files
		if (!strings.Contains(archiveFile.Name, "/rules/") ||
			archiveFile.FileInfo().IsDir()) &&
			archiveFile.FileInfo().Name() != owaspConfExampleFileName {
			continue
		}

		// Checking if owasp folder exist and creating it if needed
		sourceDir := filepath.Join(downloadedRulesDir, "owasp")
		_, err = os.Stat(sourceDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				subErr := os.MkdirAll(sourceDir, 0755)
				if subErr != nil {
					log.Warn().Err(subErr).Msgf("Error while creating coraza configuration target directory %s", sourceDir)
					return false
				}
			} else {
				log.Warn().Err(err).Msgf("Error while accessing coraza configuration target directory %s", sourceDir)
			}
		}

		// Creating an empty ruleset file
		filePath := filepath.Join(downloadedRulesDir, "owasp", archiveFile.FileInfo().Name())
		// Special path for OWASP conf example
		if archiveFile.FileInfo().Name() == owaspConfExampleFileName {
			filePath = OwaspConfExamplePath
		}
		file, err := os.Create(filePath)
		if err != nil {
			log.Warn().Err(err).Msgf("Error while creating file at %s", filePath)
			return false
		}

		// Put content in file
		size, err := io.Copy(file, tr)
		log.Debug().Msgf("Successfully written file %s of %d bytes", file.Name(), size)
		file.Close()
	}
	return true
}

/*
Download the file at the target Url to the local path
*/
func downloadUrlFile(targetUrl string, targetPath string) bool {
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
		log.Warn().Err(err).Msgf("Error while getting file from url %s", targetUrl)
		return false
	}
	if resp.StatusCode != 200 {
		log.Warn().Msgf("Received non 200 response code while fetching file from url %s", targetUrl)
		return false
	}
	defer resp.Body.Close()

	// Checking if target file directory exist and creating it if needed
	lastSlash := strings.LastIndexByte(targetPath, '/')
	sourceDir := targetPath[0:lastSlash]
	_, err = os.Stat(sourceDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			subErr := os.MkdirAll(sourceDir, 0755)
			if subErr != nil {
				log.Warn().Err(subErr).Msgf("Error while creating coraza configuration target directory %s", sourceDir)
				return false
			}
		} else {
			log.Warn().Err(err).Msgf("Error while accessing coraza configuration target directory %s", sourceDir)
		}
	}

	// Create blank file
	file, err := os.Create(targetPath)
	if err != nil {
		log.Warn().Err(err).Msgf("Error while creating file at %s", targetPath)
		return false
	}
	// Put content on file
	_, err = io.Copy(file, resp.Body)
	defer file.Close()
	if err != nil {
		log.Warn().Err(err).Msgf("Error while writing downloaded file %s at %s", targetUrl, targetPath)
	}

	log.Info().Msgf("Successfully download %s to %s ", targetUrl, targetPath)
	return true
}
