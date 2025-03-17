root=docsgen
destination=tmp/c3/cb-mpc
dataPath=$(root)/data

.PHONY: dev-setup
dev-setup:
	rm -rf node_modules
	rm -rf $(root)/tmp
	go install github.com/air-verse/air@latest
	mkdir -p                  $(root)/$(destination)/static
	cp $(dataPath)/logo.png   $(root)/$(destination)/static
	npm install tailwindcss @tailwindcss/cli
	npm install

.PHONY: dev
dev:
	cd $(root) && air -c .air.toml

.PHONY: dev-css
dev-css:
	cd $(root) && npx @tailwindcss/cli -i input.css -o $(destination)/static/output.css --watch

.PHONY: dev-serve
dev-serve:
	cd $(root)/tmp && python3 -m http.server 8000


.PHONY: ci
ci:
	rm -f docs/index.html
	cd $(root) && /usr/local/go/bin/go build -o render_app && ./render_app false data ../docs

.PHONY: build
build:
	mkdir -p docs/static
	cp $(dataPath)/logo.png docs/static
	rm -f docs/index.html
	cd $(root) && go build -o render_app && ./render_app false data ../docs
	cd $(root) && npx @tailwindcss/cli -i input.css -o ../docs/static/output.css
