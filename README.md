# IAmAdmin!

A fast, multi-threaded admin portal credential checker written in Go with Chrome TLS fingerprinting.

## Features

- Filters credentials to admin URLs only (`admin.`, `admin-`, `/admin`)
- Automatically cleans, deduplicates, and rewrites the input file
- Chrome 133 TLS fingerprint via `bogdanfinn/tls-client`
- Smart HTML form detection — finds email/password fields across any framework
- Anti-CSRF token extraction (hidden inputs, meta tags, JS variables)
- Follows POST redirects intelligently to judge the real landing page
- 100+ fail/success patterns across 10 languages and major frameworks
- Colored console output with live progress counter
- Outputs hits to `found.txt`, per-site files in `results/`, and everything to `all.log`

## Requirements

- [Go 1.21+](https://go.dev/dl/)

## Installation

```bash
git clone https://github.com/yourname/go-portalscan
cd go-portalscan
go build -o portalscan ulp.go
```
![preview](https://i.ibb.co/7xJ8kFLv/A8-ACCF18-AD5-E-49-C7-BAA5-70-F847-AF44-F0.png)

## Usage

```bash
./portalscan -f credentials.txt -t 50
```

Or run without flags for interactive prompts:

```bash
./portalscan
Enter credentials file path: credentials.txt
Enter number of threads: 50
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-f` | _(prompt)_ | Path to credentials file |
| `-t` | _(prompt)_ | Number of concurrent threads |
| `-o` | `found.txt` | Output file for hits |
| `-debug` | `false` | Dump raw HTML responses to `debug_*.html` |

## Credential Format

One entry per line:

```
host:email:password
```

**Example:**
```
admin.example.com:user@example.com:password123
admin-panel.site.co.uk:admin@site.co.uk:secret
```

Lines that don't match `admin.`, `admin-`, or `/admin` are removed automatically. Invalid hosts, bad TLDs, and duplicates are also stripped before scanning begins.

## Output

| File | Contents |
|------|----------|
| `found.txt` | All hits — `email:pass \| url` |
| `results/valid_{host}.txt` | Per-site hits |
| `all.log` | Every result (HIT / FAIL / SKIP / ERR) |

## Debug Mode

```bash
./portalscan -f credentials.txt -t 10 -debug
```

Dumps the raw GET response and failed POST responses to `debug_*.html` files for inspection.
