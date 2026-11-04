// Command gen refreshes internal/eol/data.json from endoflife.date. Run it from
// the repository root before a release:
//
//	go run ./internal/eol/gen
//
// It runs only on a developer's machine; the audit itself never contacts
// endoflife.date.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// products are the endoflife.date IDs the stack check judges.
var products = []string{
	"redis", "valkey", "mysql", "mariadb", "postgresql", "mongodb", "sqlite",
	"nodejs", "python", "ruby", "php", "go",
	"eclipse-temurin", "azul-zulu", "amazon-corretto", "oracle-jdk", "openjdk-builds-from-oracle",
	"nginx", "apache-http-server", "haproxy", "docker-engine", "containerd",
}

type release struct {
	Cycle  string `json:"cycle"`
	EOL    string `json:"eol,omitempty"`
	Ended  bool   `json:"ended,omitempty"`
	Latest string `json:"latest,omitempty"`
}

type apiRelease struct {
	Name    string  `json:"name"`
	IsEol   bool    `json:"isEol"`
	EolFrom *string `json:"eolFrom"`
	Latest  *struct {
		Name string `json:"name"`
	} `json:"latest"`
}

func fetch(client *http.Client, product string) ([]release, error) {
	req, err := http.NewRequest(http.MethodGet, "https://endoflife.date/api/v1/products/"+product, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ubuntu-sys-audit-eol-gen")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", product, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Result struct {
			Releases []apiRelease `json:"releases"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", product, err)
	}
	var out []release
	for _, r := range doc.Result.Releases {
		rel := release{Cycle: r.Name}
		if r.EolFrom != nil {
			if _, err := time.Parse("2006-01-02", *r.EolFrom); err != nil {
				return nil, fmt.Errorf("%s %s: bad eolFrom %q", product, r.Name, *r.EolFrom)
			}
			rel.EOL = *r.EolFrom
		} else if r.IsEol {
			rel.Ended = true
		}
		if r.Latest != nil {
			rel.Latest = r.Latest.Name
		}
		out = append(out, rel)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no releases", product)
	}
	return out, nil
}

func main() {
	outPath := flag.String("o", "internal/eol/data.json", "file to write")
	flag.Parse()
	client := &http.Client{Timeout: 30 * time.Second}
	all := map[string][]release{}
	for _, p := range products {
		rels, err := fetch(client, p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
		all[p] = rels
	}
	doc := struct {
		Source    string               `json:"source"`
		Generated string               `json:"generated"`
		Products  map[string][]release `json:"products"`
	}{"https://endoflife.date", time.Now().UTC().Format("2006-01-02"), all}
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s: %d products\n", *outPath, len(all))
}
