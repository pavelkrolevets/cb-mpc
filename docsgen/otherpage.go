package main

import (
	"fmt"
	"path/filepath"
)

// ====================================================
// Render each sub-page
// ====================================================
func RenderOtherPages(pageNames []string, dataPath, destinationPath string) error {
	for _, pageName := range pageNames {
		// Copy data.js to docs/static/...
		if err := copyFile(
			filepath.Join(dataPath, "individual_benchmarks", pageName, "data.js"),
			filepath.Join(destinationPath, "static", pageName, "data.js"),
		); err != nil {
			return err
		}

		type Data struct {
			Name      string
			PageNames []string
		}
		data := Data{
			Name:      filepath.Join("static", pageName, "data.js"),
			PageNames: pageNames,
		}

		// Render bench.html for each page
		if err := ExecuteTemplate(
			fmt.Sprintf("%s/%s.html", destinationPath, pageName),
			data,
			"templates/pages/bench.html",
		); err != nil {
			return err
		}
	}
	return nil
}
