package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type Subdomain struct {
	Subdomain string `json:"subdomain"`
}

type Port struct {
	Port   string `json:"port"`
	Status string `json:"status"`
}

type HttpxResult struct {
	Subdomain string `json:"subdomain"`
	Status    string `json:"status"`
	Port      string `json:"port"`
}

type ScanRequest struct {
	Domain string `json:"domain"`
}

type ScanResponse struct {
	Subdomains   []Subdomain   `json:"subdomains"`
	OpenPorts    []Port        `json:"openPorts"`
	HttpxResults []HttpxResult `json:"httpxResults"`
	Status       string        `json:"status,omitempty"`
	Message      string        `json:"message,omitempty"`
}

var (
	scanResults = make(map[string]ScanResponse)
	scanMutex   sync.RWMutex
	wg          sync.WaitGroup
)

func checkToolInstalled(toolName string) bool {
	_, err := exec.LookPath(toolName)
	return err == nil
}

func isValidDomain(domain string) bool {
	return len(domain) > 0 && !strings.Contains(domain, " ") && strings.Contains(domain, ".")
}

func subdomainScan(domain string, ch chan<- []string) {
	defer wg.Done()
	log.Printf("Starting subdomain scan for domain: %s", domain)

	if !checkToolInstalled("subfinder") {
		log.Println("Error: subfinder is not installed")
		ch <- []string{}
		return
	}

	cmd := exec.Command("subfinder", "-d", domain, "-silent")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error running subfinder for domain %s: %v", domain, err)
		ch <- []string{}
		return
	}

	subdomains := strings.Split(strings.TrimSpace(string(output)), "\n")
	var validSubdomains []string
	for _, sub := range subdomains {
		if sub != "" {
			validSubdomains = append(validSubdomains, sub)
		}
	}

	log.Printf("Found %d subdomains for %s", len(validSubdomains), domain)
	ch <- validSubdomains
}

func portScan(domain string, ch chan<- []Port) {
	defer wg.Done()
	log.Printf("Starting port scan for domain: %s", domain)

	if !checkToolInstalled("nmap") {
		log.Println("Error: nmap is not installed")
		ch <- []Port{}
		return
	}

	cmd := exec.Command("nmap", "-p80,443,8080,8443", "-T4", domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error running nmap for domain %s: %v", domain, err)
		ch <- []Port{}
		return
	}

	var openPorts []Port
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				port := strings.Split(parts[0], "/")[0]
				openPorts = append(openPorts, Port{
					Port:   port,
					Status: "open",
				})
			}
		}
	}

	log.Printf("Found %d open ports for %s", len(openPorts), domain)
	ch <- openPorts
}

func httpxScan(subdomains []string, ch chan<- []HttpxResult, domain string) {
	defer wg.Done()
	log.Println("Starting HTTPx scan")

	if !checkToolInstalled("httpx") {
		log.Println("Error: httpx is not installed")
		ch <- []HttpxResult{}
		return
	}

	var results []HttpxResult

	// Create a file to store the results of the status codes
	fileName := fmt.Sprintf("%s_status_codes.txt", domain)
	file, err := os.Create(fileName)
	if err != nil {
		log.Printf("Error creating file %s: %v", fileName, err)
		ch <- []HttpxResult{}
		return
	}
	defer file.Close()

	for _, sub := range subdomains {
		for _, port := range []string{"80", "443"} {
			target := fmt.Sprintf("http://%s:%s", sub, port)
			cmd := exec.Command("httpx", "-u", target, "-silent", "-status-code")
			output, err := cmd.CombinedOutput()

			result := HttpxResult{
				Subdomain: sub,
				Port:      port,
			}

			if err != nil {
				result.Status = "Error"
			} else {
				result.Status = strings.TrimSpace(string(output))
			}

			// Write result to the file
			_, err = fmt.Fprintf(file, "%s:%s - %s\n", sub, port, result.Status)
			if err != nil {
				log.Printf("Error writing to file %s: %v", fileName, err)
			}

			results = append(results, result)
		}
	}

	log.Printf("HTTPx scan completed with %d results", len(results))
	ch <- results
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(ScanResponse{
			Status:  "error",
			Message: "Invalid request body",
		})
		return
	}

	if !isValidDomain(req.Domain) {
		json.NewEncoder(w).Encode(ScanResponse{
			Status:  "error",
			Message: "Invalid domain format",
		})
		return
	}

	// Create channels for scan results
	subdomainChan := make(chan []string)
	portChan := make(chan []Port)
	httpxChan := make(chan []HttpxResult)

	// Start scanning processes
	wg.Add(2)
	go subdomainScan(req.Domain, subdomainChan)
	go portScan(req.Domain, portChan)

	// Start HTTPx scan after subdomains are found
	go func() {
		subdomains := <-subdomainChan
		if len(subdomains) > 0 {
			wg.Add(1)
			go httpxScan(subdomains, httpxChan, req.Domain)
		} else {
			httpxChan <- []HttpxResult{}
		}
	}()

	// Process results
	go func() {
		wg.Wait()
		scanMutex.Lock()
		defer scanMutex.Unlock()

		results := ScanResponse{
			OpenPorts: <-portChan,
			Status:    "completed",
		}

		subdomains := <-subdomainChan
		results.Subdomains = make([]Subdomain, len(subdomains))
		for i, sub := range subdomains {
			results.Subdomains[i] = Subdomain{Subdomain: sub}
		}

		results.HttpxResults = <-httpxChan
		scanResults[req.Domain] = results
	}()

	json.NewEncoder(w).Encode(ScanResponse{
		Status:  "scanning",
		Message: "Scan started for " + req.Domain,
	})
}

func getScanResultsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	vars := mux.Vars(r)
	domain := vars["domain"]

	scanMutex.RLock()
	results, exists := scanResults[domain]
	scanMutex.RUnlock()

	if !exists {
		json.NewEncoder(w).Encode(ScanResponse{
			Status:  "pending",
			Message: "Scan in progress or not found",
		})
		return
	}

	json.NewEncoder(w).Encode(results)
}

func getScanFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := vars["domain"]

	// Check if the file exists
	fileName := fmt.Sprintf("%s_status_codes.txt", domain)
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		json.NewEncoder(w).Encode(ScanResponse{
			Status:  "error",
			Message: "Scan results file not found or still being generated.",
		})
		return
	}

	// Set the response headers to indicate a file download
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)

	// Serve the file
	http.ServeFile(w, r, fileName)
}

func main() {
	requiredTools := []string{"subfinder", "nmap", "httpx"}
	for _, tool := range requiredTools {
		if !checkToolInstalled(tool) {
			log.Printf("Warning: %s is not installed", tool)
		}
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/scan", scanHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/scan/{domain}", getScanResultsHandler).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/scan/{domain}/file", getScanFileHandler).Methods("GET", "OPTIONS")

	corsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{"http://localhost:5173", "http://127.0.0.1:5173"}), // Update with your frontend URL
		handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Accept"}),
	)

	server := &http.Server{
		Addr:    ":5000",
		Handler: corsHandler(router),
	}

	log.Println("Server starting on http://localhost:5000")
	log.Fatal(server.ListenAndServe())
}
