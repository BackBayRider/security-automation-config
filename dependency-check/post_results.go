package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const (
	defaultRequestTimeout             = 60
	maxPostLength                     = 16383
	gitlabJobNameOWASPDependencyCheck = "owasp-dependency-check"
	jsonReportPath                    = "Reports/OWASP/dependency-check-report.json"
	htmlReportPath                    = "Reports/OWASP/dependency-check-report.html"
	botUsername                       = "Dependency-Check"
	//botIcon              = "https://www.mattermost.org/wp-content/uploads/2016/04/icon.png"
)

type Server struct {
	Client                *http.Client
	GitlabUrl             string
	GitlabToken           string
	MattermostWebhookSAST string
}

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

func main() {
	s, err := New()
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout*time.Second)
	defer cancel()

	serverHost, ok := os.LookupEnv("CI_SERVER_HOST")
	if !ok {
		log.Fatalf("not set %v", "CI_SERVER_HOST")
	}
	projectName, ok := os.LookupEnv("CI_PROJECT_NAME")
	if !ok {
		log.Fatalf("not set %v", "CI_PROJECT_NAME")
	}
	projectNamespace, ok := os.LookupEnv("CI_PROJECT_NAMESPACE")
	if !ok {
		log.Fatalf("not set %v", "CI_PROJECT_NAMESPACE")
	}
	projectID, ok := os.LookupEnv("CI_PROJECT_ID")
	if !ok {
		log.Fatalf("not set %v", "CI_PROJECT_ID")
	}
	ref, ok := os.LookupEnv("CI_COMMIT_REF_NAME")
	if !ok {
		log.Fatalf("not set %v", "CI_COMMIT_REF_NAME")
	}
	//jobName, ok := os.LookupEnv("CI_JOB_NAME")
	//if !ok {
	//	log.Fatalf("not set %v", "CI_JOB_NAME")
	//}
	pipelineIID, ok := os.LookupEnv("CI_PIPELINE_IID")
	if !ok {
		log.Fatalf("not set %v", "CI_PIPELINE_IID")
	}
	jobToken, ok := os.LookupEnv("CI_JOB_TOKEN")
	if !ok {
		log.Fatalf("not set %v", "CI_JOB_TOKEN")
	}

	artifacts, err := s.getArtifacts(ctx, projectID, ref, gitlabJobNameOWASPDependencyCheck)
	if err != nil {
		fmt.Println("Could not load artifacts: ", err)
		os.Exit(1)
	}

	var artifactUrl string
	for _, artifact := range artifacts {
		if artifact.Path == htmlReportPath {
			artifactUrl = artifact.URL
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
			if ref != "" {
				ref = fmt.Sprintf(", triggered by %s", ref)
			}
			header := fmt.Sprintf("%v in `%v` GitLab [#%v](https://gitlab-ci-token:%v@%v/%v/%v/-/pipelines/%v)%v", findings, projectName, pipelineIID, jobToken, serverHost, projectNamespace, projectName, pipelineIID, ref)
			body := report.summarize(artifactUrl)
			footer := fmt.Sprintf("View the full report [here](%s) or [edit suppressions](https://github.com/mattermost/security-automation-config/edit/master/dependency-check/suppression.%v.xml).", artifactUrl, strings.Split(projectName, "/")[1])

			summary := fmt.Sprintf("%s\n\n%s\n%s", header, body, footer)
			if len(summary) > maxPostLength {
				summary = fmt.Sprintf("%s\n\n---\n**Summary table exceeds maximum post length and has been omitted.**\n\n---\n%s", header, footer)
			}

			webhookPayload := &Payload{Username: botUsername, Text: summary}
			if err := s.sendToWebhook(ctx, s.MattermostWebhookSAST, webhookPayload); err != nil {
				fmt.Println("Failed to post to webhook: ", err)
				os.Exit(1)
			}

			break
		}
	}
}

func New() (*Server, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	gitlabUrl, ok := os.LookupEnv("GITLAB_URL")
	if !ok {
		log.Fatalf("not set %v", "GITLAB_URL")
	}
	gitlabToken, ok := os.LookupEnv("GITLAB_TOKEN")
	if !ok {
		log.Fatalf("not set %v", "GITLAB_TOKEN")
	}
	mattermostWebhookSAST, ok := os.LookupEnv("MATTERMOST_WEBHOOK_SAST")
	if !ok {
		log.Fatalf("not set %v", "MATTERMOST_WEBHOOK_SAST")
	}

	s := &Server{
		Client:                http.DefaultClient,
		GitlabUrl:             gitlabUrl,
		GitlabToken:           gitlabToken,
		MattermostWebhookSAST: mattermostWebhookSAST,
	}

	return s, nil
}

func (s *Server) getArtifacts(ctx context.Context, projectID string, ref string, jobName string) ([]circleCIArtifact, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(s.GitlabUrl+"/api/v4/projects/"+projectID+"/jobs/artifacts/"+ref+"/download?job="+jobName), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Add("private-token", s.GitlabToken)
	res, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	closeBody(res)

	var response []circleCIArtifact
	err = json.Unmarshal(body, &response)
	return response, err
}

func downloadReport(url string) (*report, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	closeBody(res)
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

func closeBody(r *http.Response) {
	if r.Body != nil {
		_, _ = io.Copy(ioutil.Discard, r.Body)
		_ = r.Body.Close()
	}
}
