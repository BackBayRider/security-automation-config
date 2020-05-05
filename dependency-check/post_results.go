package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	maxPostLength        = 16383
	circleCIArtifactsURL = "https://circleci.com/api/v1.1/project/gh/%s/%s/artifacts"
	jsonReportPath       = "Reports/OWASP/dependency-check-report.json"
	htmlReportPath       = "Reports/OWASP/dependency-check-report.html"
	botUsername          = "Dependency-Check"
	botIcon              = "https://www.mattermost.org/wp-content/uploads/2016/04/icon.png"
)

type circleCIArtifact struct {
	Path string
	URL  string
}

type report struct {
	Dependencies []dependency
}

type dependency struct {
	FileName         string
	Vulnerabilities  vulnerabilityList
	VulnerabilityIDs vulnerabilityIDList
}

type vulnerability struct {
	Name     string
	Severity string
	Source   string
}

type vulnerabilityList []vulnerability

type vulnerabilityID struct {
	ID string
}

type vulnerabilityIDList []vulnerabilityID

type webhookRequest struct {
	Username string `json:"username"`
	IconURL  string `json:"icon_url"`
	Text     string `json:"text"`
}

func main() {
	var (
		project = os.Getenv("CIRCLE_PROJECT_REPONAME")
		repo    = fmt.Sprintf("%s/%s", os.Getenv("CIRCLE_PROJECT_USERNAME"), project)
		build   = os.Getenv("CIRCLE_BUILD_NUM")
		pr      = os.Getenv("CIRCLE_PULL_REQUEST")
		webhook = os.Getenv("SAST_WEBHOOK_URL")
	)

	artifacts, err := getArtifacts(repo, build)
	if err != nil {
		fmt.Println("Could not load artifacts: ", err)
		os.Exit(1)
	}

	var url string
	for _, artifact := range artifacts {
		if artifact.Path == htmlReportPath {
			url = artifact.URL
		}
	}
	for _, artifact := range artifacts {
		if artifact.Path == jsonReportPath {

			report, err := downloadReport(artifact.URL)
			if err != nil {
				fmt.Println("Could not load report: ", err)
				os.Exit(1)
			}

			count := report.getVulnerabilityCount()
			if count == 0 {
				break
			}

			findings := "New finding"
			if count > 1 {
				findings = fmt.Sprintf("%d new findings", count)
			}
			if pr != "" {
				pr = fmt.Sprintf(", triggered by %s", pr)
			}
			header := fmt.Sprintf("%s in `%s` CircleCI build [#%s](https://circleci.com/gh/%s/%s)%s", findings, repo, build, repo, build, pr)
			body := report.summarize(url)
			footer := fmt.Sprintf("View the full report [here](%s) or [edit suppressions](https://github.com/mattermost/security-automation-config/edit/master/dependency-check/suppression.%s.xml).", url, strings.Split(repo, "/")[1])

			summary := fmt.Sprintf("%s\n\n%s\n%s", header, body, footer)
			if len(summary) > maxPostLength {
				summary = fmt.Sprintf("%s\n\n---\n**Summary table exceeds maximum post length and has been omitted.**\n\n---\n%s", header, footer)
			}

			if err := postToWebhook(webhook, summary); err != nil {
				fmt.Println("Failed to post to webhook: ", err)
				os.Exit(1)
			}

			break
		}
	}
}

func postToWebhook(webhook, message string) error {
	payload, err := json.Marshal(webhookRequest{
		Username: botUsername, IconURL: botIcon, Text: message,
	})
	if err != nil {
		return err
	}
	res, err := http.PostForm(webhook, url.Values{"payload": {string(payload)}})
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("webhook returned %d %s", res.StatusCode, res.Status)
	}
	return nil
}

func getArtifacts(repo, build string) ([]circleCIArtifact, error) {
	req, _ := http.NewRequest("GET", fmt.Sprintf(circleCIArtifactsURL, repo, build), nil)
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	response := []circleCIArtifact{}
	err = json.Unmarshal(body, &response)
	return response, err
}

func downloadReport(url string) (*report, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	body, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	response := &report{}
	err = json.Unmarshal(body, &response)
	return response, err
}

func (r *report) getVulnerabilityCount() int {
	count := 0
	for _, dependency := range r.Dependencies {
		count += len(dependency.Vulnerabilities)
	}
	return count
}

func (r *report) summarize(url string) string {

	htmlReport := make([]byte, 0)
	res, err := http.Get(url)
	if err == nil {
		htmlReport, _ = ioutil.ReadAll(res.Body)
	}

	summary := "|Dependency|CPEs|CVEs|Severity|\n|----------|----|----|--------|\n"

	for i, dependency := range r.Dependencies {
		if len(dependency.Vulnerabilities) == 0 {
			continue
		}

		link := fmt.Sprintf("[%s](%s%s)", dependency.FileName, url, findReferenceOnHTMLReport(htmlReport, i))
		summary = fmt.Sprintf("%s|%s|%s|%s|`%s`|\n", summary, link,
			dependency.VulnerabilityIDs.summarize(),
			dependency.Vulnerabilities.summarize(),
			dependency.Vulnerabilities.getHighestSeverity())
	}

	return summary
}

func (v vulnerabilityList) getHighestSeverity() string {
	severity := "Unknown"
	for _, vulnerability := range v {
		switch vulnerability.Severity {
		case "HIGH":
			severity = "HIGH"
		case "MEDIUM":
			if severity != "HIGH" {
				severity = "MEDIUM"
			}
		case "LOW":
			if severity == "Unknown" {
				severity = "LOW"
			}
		}
	}
	return severity
}

func (v vulnerabilityList) summarize() string {
	summary := make([]string, 0, len(v))
	for _, vulnerability := range v {
		switch vulnerability.Source {
		case "NVD":
			summary = append(summary, fmt.Sprintf("[`%s`](https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s)", vulnerability.Name, vulnerability.Name))
		case "NPM":
			summary = append(summary, fmt.Sprintf("[`NPM-%s`](https://www.npmjs.com/advisories/%s)", vulnerability.Name, vulnerability.Name))
		default:
			summary = append(summary, fmt.Sprintf("`%s`", vulnerability.Name))
		}
	}
	return strings.Join(summary, ", ")
}

func (v vulnerabilityIDList) summarize() string {
	summary := make([]string, 0, len(v))
	for _, id := range v {
		summary = append(summary, fmt.Sprintf("`%s`", id.ID))
	}
	return strings.Join(summary, ", ")
}

func findReferenceOnHTMLReport(report []byte, i int) []byte {
	marker := []byte(fmt.Sprintf("#l%d_", i+1))
	pos := bytes.Index(report, marker)
	return report[pos : pos+len(marker)+40]
}
