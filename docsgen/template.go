package main

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

// ExecuteTemplate loads main.html + partial templates and renders to file.
func ExecuteTemplate(path string, data any, names ...string) error {
	tmpl := ParseTemplate(names...)

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		return err
	}
	return nil
}

func ParseTemplate(names ...string) *template.Template {
	global := []string{
		filepath.Join("templates", "main.html"),
		filepath.Join("templates", "pages", "simple-table.html"),
		filepath.Join("templates", "pages", "2pc-table.html"),
		filepath.Join("templates", "pages", "mpc-table.html"),
	}

	pagePath := filepath.Join(names...)
	global = append(global, pagePath)

	funcMap := template.FuncMap{
		"inc": func(i int) int {
			return i + 1
		},
		"until": func(n int) []int {
			arr := make([]int, n)
			for i := 0; i < n; i++ {
				arr[i] = i
			}
			return arr
		},
		"contains": func(str, substr string) bool {
			return strings.Contains(str, substr)
		},
	}

	return template.Must(template.New("main.html").Funcs(funcMap).ParseFiles(global...))
}
