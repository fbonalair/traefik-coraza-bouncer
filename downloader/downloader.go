package downloader

import (
	"archive/tar"
	"compress/gzip"
	"github.com/fbonalair/traefik-coraza-bouncer/coraza"
	"github.com/fbonalair/traefik-coraza-bouncer/utils"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Coraza default recommended configuration
const (
	corazaConfUrl = "https://raw.githubusercontent.com/jptosso/coraza-waf/v2/master/coraza.conf-recommended"
	// TODO dynamise version
	coreRulesetUrl = "https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.2.tar.gz"
)

var (
	rulesDir                  = utils.GetOptionalEnv(coraza.BouncerSecRulesPath, coraza.BouncerSecRulesPathDefault)
	corazaConfPath            = filepath.Join(rulesDir, "coraza.conf")
	activeDownload            = utils.GetOptionalEnv(coraza.BouncerSecRulesOwasp, "true")
	coreRulesetArchivePath    = filepath.Join("/tmp", "coreruleset.tar.gz") // TODO use temp dir ioutil.TempDir or os.TempDir()
	corazaRecommendedFilePath = "coraza.conf-recommended"                   // TODO format to path

)

func DownloadCorazaRecommendation(targetDir string) bool { // FIXME use targetDir
	return downloadUrlFile(corazaConfUrl, corazaConfPath)
}

func DownloadOwaspCoreRules(targetDir string) bool {
	success := downloadUrlFile(coreRulesetUrl, coreRulesetArchivePath)
	if !success {
		return false
	}
	// TODO Verify archive with SHA

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
			archiveFile.FileInfo().Name() != "crs-setup.conf.example" {
			continue
		}

		// Creating an empty ruleset file
		filePath := filepath.Join(rulesDir, "owasp", archiveFile.FileInfo().Name())
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
