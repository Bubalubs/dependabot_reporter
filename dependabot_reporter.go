package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Token        string `yaml:"github_token"`
	OutputFormat string `yaml:"output_format"`
}

type DependabotAlert struct {
	Dependency struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
		Scope        string `json:"scope"`
	} `json:"dependency"`
	SecurityAdvisory struct {
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	} `json:"security_advisory"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
}

var (
	configFile   string
	outputFormat string
	repo         string
)

func main() {
	flag.StringVar(&configFile, "config", "config.yaml", "Path to configuration file")
	flag.StringVar(&outputFormat, "output", "", "Output format (json or csv)")
	flag.StringVar(&repo, "repo", "", "Repository in owner/repo format")
	flag.Parse()

	config := loadConfig(configFile)

	if outputFormat != "" {
		config.OutputFormat = outputFormat
	}

	if outputFormat == "" && config.OutputFormat == "" {
		config.OutputFormat = "json"
	}

	if repo == "" {
		log.Fatal("Repository is required. Provide it using the --repo flag.")
	}

	if config.OutputFormat != "json" && config.OutputFormat != "csv" {
		log.Fatal("Unsupported output format. Use 'json' or 'csv'.")
	}

	if config.Token == "" {
		log.Fatal("Github Personal Access token is required. Please set it in your config.yaml file (See config.yaml.example) or as the DEPENDABOT_TOKEN environment variable.")
	}

	log.Printf("Fetching alerts from repository %s...", repo)
	alerts := fetchDependabotAlerts(config.Token, repo)

	if len(alerts) == 0 {
		fmt.Println("No open Dependabot alerts found. Congratulations! :)")
		return
	}

	log.Printf("Found %d open Dependabot alerts!", len(alerts))

	log.Printf("Exporting alerts to %s format...", config.OutputFormat)

	switch config.OutputFormat {
	case "json":
		exportJSON(alerts)
	case "csv":
		exportCSV(alerts, repo)
	}
}

func loadConfig(path string) Config {
	var config Config
	data, err := os.ReadFile(path)
	if err == nil {
		err = yaml.Unmarshal(data, &config)
		if err != nil {
			log.Fatalf("Error parsing config file: %v", err)
		}
	}

	if token := os.Getenv("DEPENDABOT_TOKEN"); token != "" {
		config.Token = token
	}

	return config
}

func fetchDependabotAlerts(token, repo string) []DependabotAlert {
	url := fmt.Sprintf("https://api.github.com/repos/%s/dependabot/alerts", repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("Error fetching alerts: %v\nResponse: %s", resp.Status, string(body))
	}

	var allAlerts []DependabotAlert
	err = json.NewDecoder(resp.Body).Decode(&allAlerts)
	if err != nil {
		log.Fatalf("Error decoding response: %v", err)
	}

	// Only return open alerts
	openAlerts := []DependabotAlert{}
	for _, alert := range allAlerts {
		if alert.State == "open" {
			openAlerts = append(openAlerts, alert)
		}
	}

	return openAlerts
}

func exportJSON(alerts []DependabotAlert) {
	data, err := json.MarshalIndent(alerts, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	err = os.WriteFile("dependabot_alerts.json", data, 0644)
	if err != nil {
		log.Fatalf("Error writing JSON file: %v", err)
	}

	fmt.Println("Alerts exported to dependabot_alerts.json")
}

func exportCSV(alerts []DependabotAlert, repo string) {
	repoName := filepath.Base(repo)
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s-alerts-%s.csv", repoName, timestamp)

	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Dependency", "Ecosystem", "Severity", "CVE", "Manifest", "Description", "URL"})

	for _, alert := range alerts {
		err := writer.Write([]string{
			alert.Dependency.Package.Name,
			alert.Dependency.Package.Ecosystem,
			alert.SecurityAdvisory.Severity,
			getCVE(alert.SecurityAdvisory.Identifiers),
			alert.Dependency.ManifestPath,
			alert.SecurityAdvisory.Description,
			alert.HTMLURL,
		})
		if err != nil {
			log.Fatalf("Error writing CSV row: %v", err)
		}
	}

	fmt.Printf("Alerts exported to %s\n", filename)
}

func getCVE(identifiers []struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}) string {
	for _, id := range identifiers {
		if id.Type == "CVE" {
			return id.Value
		}
	}
	return "N/A"
}
