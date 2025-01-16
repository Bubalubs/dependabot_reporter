package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"
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

func main() {
	app := &cli.App{
		Name:  "Dependabot Alerts Fetcher",
		Usage: "Fetch and export open Dependabot alerts from a GitHub repository",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to configuration file",
				Value:   "config.yaml",
				EnvVars: []string{"CONFIG_PATH"},
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output format (json or csv)",
				EnvVars: []string{"OUTPUT_FORMAT"},
			},
			&cli.StringFlag{
				Name:     "repo",
				Aliases:  []string{"r"},
				Usage:    "Repository in owner/repo format",
				Required: true,
			},
		},
		Action: func(c *cli.Context) error {
			configFile := c.String("config")
			outputFormat := c.String("output")
			repo := c.String("repo")

			config := loadConfig(configFile)

			if outputFormat != "" {
				config.OutputFormat = outputFormat
			}

			if config.OutputFormat == "" {
				config.OutputFormat = "json"
			}

			if config.OutputFormat != "json" && config.OutputFormat != "csv" {
				return fmt.Errorf("unsupported output format: use 'json' or 'csv'")
			}

			if config.Token == "" {
				return fmt.Errorf("GitHub personal access token is required. Set it in your config file or as the DEPENDABOT_TOKEN environment variable")
			}

			log.Printf("Fetching alerts from repository %s...", repo)
			alerts := fetchDependabotAlerts(config.Token, repo)

			if len(alerts) == 0 {
				fmt.Println("No open Dependabot alerts found. Congratulations! :)")
				return nil
			}

			log.Printf("Found %d open Dependabot alerts!", len(alerts))
			log.Printf("Exporting alerts to %s format...", config.OutputFormat)

			switch config.OutputFormat {
			case "json":
				exportJSON(alerts, repo)
			case "csv":
				exportCSV(alerts, repo)
			}

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
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

	openAlerts := []DependabotAlert{}
	for _, alert := range allAlerts {
		if alert.State == "open" {
			openAlerts = append(openAlerts, alert)
		}
	}

	return openAlerts
}

func exportJSON(alerts []DependabotAlert, repo string) {
	repoName := filepath.Base(repo)
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s-alerts-%s.json", repoName, timestamp)

	dir := ensureReportsDir()
	filePath := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(alerts, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		log.Fatalf("Error writing JSON file: %v", err)
	}

	fmt.Printf("Alerts exported to %s\n", filePath)
}

func exportCSV(alerts []DependabotAlert, repo string) {
	dir := ensureReportsDir()
	repoName := filepath.Base(repo)
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s-alerts-%s.csv", repoName, timestamp)
	filePath := filepath.Join(dir, filename)

	file, err := os.Create(filePath)
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

	fmt.Printf("Exported %d alerts to %s\n", len(alerts), filePath)
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

func ensureReportsDir() string {
	dir := "reports"
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		log.Fatalf("Error creating reports directory: %v", err)
	}
	return dir
}
