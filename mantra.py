#!/usr/bin/env python3
"""
mantra.py - a pure-Python (standard library only) port of mantra.

Hunts for leaked API keys / secrets in JavaScript files and HTML pages.
Reads URLs from stdin, one per line:

    cat js.txt | python3 mantra.py
    cat js.txt | python3 mantra.py -t 100 -d -ep 'my_custom_[a-z]{10}'

Only use it on targets you own or are authorised to test.
"""

import argparse
import re
import ssl
import sys
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ----------------------------------------------------------------------------
# ANSI colours (same scheme as the Go version)
# ----------------------------------------------------------------------------
RED = "\033[31m"
GREEN = "\033[32m"
BGREEN = "\033[1;32m"
YELLOW = "\033[33m"
WHITE = "\033[37m"
RESET = "\033[0m"

BANNER = (
    RED
    + r"""
███╗   ███╗ █████╗ ███╗   ██╗████████╗██████╗  █████╗
████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗
██╔████╔██║███████║██╔██╗ ██║   ██║   ██████╔╝███████║
██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██╔══██╗██╔══██║
██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║  ██║██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
"""
    + RED + "[" + WHITE + "By Vrsblk" + RED + "]\n" + RESET
)

# ----------------------------------------------------------------------------
# Patterns
# ----------------------------------------------------------------------------

# Hand-written patterns for well-known key formats.
FIXED_PATTERNS = [
    r'COGNITO_IDENTITY[A-Z0-9_]*:\s*"[^"]+"',
    r'(?P<key>CANDEX_[A-Z_]+):\s*"(?P<value>[^"]+)"',
    r'REACT_APP_[A-Z_]+:\s*"([^"]+)"',
    r"com\.amplify\.Cognito\.[a-z0-9-]+\.([a-zA-Z0-9]+)\.identityId",
    r"Basic [A-Za-z0-9+/]{15}",
    r"xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}",
    r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    r"(?i)facebook.{0,30}['\"\s][0-9a-f]{32}['\"\s]",
    r"(?i)twitter.{0,30}['\"\s][0-9a-zA-Z]{35,44}['\"\s]",
    r"(?i)heroku.{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    r"key-[0-9a-zA-Z]{32}",
    r"[0-9a-f]{32}-us[0-9]{1,2}",
    r"sk_live_[0-9a-z]{32}",
    r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"6L[0-9A-Za-z\-_]{38}",
    r"ya29\.[0-9A-Za-z\-_]+",
    r"AKIA[0-9A-Z]{16}",
    r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    r"s3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com",
    r"EAACEdEose0cBA[0-9A-Za-z]+",
    r"SK[0-9a-fA-F]{32}",
    r"AC[a-zA-Z0-9_\-]{32}",
    r"AP[a-zA-Z0-9_\-]{32}",
    r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    r"sq0csp-[ 0-9A-Za-z\-_]{43}",
    r"sqOatp-[0-9A-Za-z\-_]{22}",
    r"sk_live_[0-9a-zA-Z]{24}",
    r"rk_live_[0-9a-zA-Z]{24}",
    r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com",
    r"-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\S]{100,}-----END PRIVATE KEY-----",
    r"-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\S]{100,}-----END RSA PRIVATE KEY-----",
    r"(?i)[\"']?air[-_]?table[-_]?api[-_]?key[\"']?[=:][\"']?.+[\"']",
    r"(?i)zendesk(_api_token|_key|_token|-travis-github|_url|_username)(\s|=)",
]

# "name = value" style patterns. Underscore in a name matches an optional
# '_' or '-', so "aws_secret_key" also catches awsSecretKey-style and
# aws-secret-key spellings (case-insensitive).
KEYWORD_TEMPLATE = (
    r"(?i)[\"']?{name}[\"']?[^\S\r\n]*[=:][^\S\r\n]*[\"']?[\w-]+[\"']?"
)

KEYWORD_NAMES = """
access_key_secret access_secret access_token account_sid adzerk_api_key
algolia_admin_key_1 algolia_admin_key_2 algolia_api_key algolia_search_api_key
algolia_search_key alicloud_access_key alicloud_secret_key amazon_secret_access_key
anaconda_token android_docs_deploy_token ansible_vault_password api_key
api_key_secret api_key_sid api_secret apiary_api_key app_secrete app_token
appclientsecret apple_id_password argos_token artifactory_key artifacts_aws_access_key_id
artifacts_aws_secret_access_key artifacts_bucket artifacts_key artifacts_secret
assistant_iam_apikey auth_token auth0_api_clientsecret auth0_client_secret
aws_access aws_access_key aws_access_key_id aws_config_accesskeyid
aws_config_secretaccesskey aws_key aws_secret aws_secret_access_key aws_secret_key
aws_secrets aws_ses_access_key_id aws_ses_secret_access_key awsaccesskeyid
awssecretkey b2_app_key b2_bucket bintray_api_key bintray_apikey bintray_gpg_password
bintray_key bintray_token bintraykey bluemix_api_key bluemix_auth bluemix_pass
bluemix_pass_prod bluemix_password bluemix_pwd bluemix_username browserstack_access_key
bucketeer_aws_access_key_id bucketeer_aws_secret_access_key bundlesize_github_token
cache_s3_secret_key cargo_token cattle_access_key cattle_secret_key censys_secret
certificate_password cf_password chrome_client_secret chrome_refresh_token
ci_deploy_password ci_user_token clojars_password client_secret cloud_api_key
cloudflare_api_key cloudflare_auth_email cloudflare_auth_key cloudinary_url
codacy_project_token codeclimate_repo_token codecov_token coveralls_api_token
coveralls_repo_token coveralls_token coverity_scan_token consumer_key consumerkey
contentful_access_token contentful_management_api_access_token cypress_record_key
database_password database_user datadog_api_key datadog_app_key db_connection
db_password db_pw db_user db_username deploy_password deploy_secure deploy_token
deploy_user dgpg_passphrase digitalocean_access_token docker_hub_password
docker_key docker_pass docker_passwd docker_password docker_token dockerhub_password
dockerhubpassword doordash_auth_token dropbox_oauth_bearer dsonar_login
elastic_cloud_auth elasticsearch_password encryption_password env_github_oauth_token
env_heroku_api_key env_key env_secret env_secret_access_key eureka_awssecretkey
exp_password file_password firebase_api_json firebase_api_token firebase_key
firebase_token flask_secret_key flickr_api_key flickr_api_secret fossa_api_key
ftp_login ftp_password ftp_pw ftp_user ftp_username gcloud_service_key gcr_password
ghost_api_key gh_api_key gh_oauth_client_secret gh_oauth_token gh_repo_token gh_token
git_token github_access_token github_api_key github_api_token github_auth
github_auth_token github_client_secret github_deployment_token github_key
github_oauth github_oauth_token github_password github_pwd github_release_token
github_token github_tokens gogs_password google_client_secret google_maps_api_key
google_private_key gpg_passphrase gpg_private_key gpg_secret_keys gradle_publish_key
gradle_publish_secret gradle_signing_password heroku_api_key heroku_token
hockeyapp_token homebrew_github_api_token ios_docs_deploy_token jdbc_databaseurl
jwt_secret kafka_admin_url keystore_pass kubeconfig leanplum_key lighthouse_api_key
linux_signing_key looker_test_runner_client_secret mailchimp_api_key mailchimp_key
mailer_password mailgun_api_key mailgun_apikey mailgun_password mailgun_priv_key
mailgun_pub_apikey mailgun_pub_key mailgun_secret_api_key mandrill_api_key
manage_key manage_secret management_token managementapiaccesstoken mapbox_access_token
mapbox_api_token mapbox_aws_access_key_id mapbox_aws_secret_access_key mapboxaccesstoken
mg_api_key mg_public_api_key minio_access_key minio_secret_key mysql_password
mysql_root_password mysqlsecret netlify_api_key new_relic_beta_token ngrok_auth_token
ngrok_token nexus_password nexuspassword node_pre_gyp_accesskeyid
node_pre_gyp_github_token node_pre_gyp_secretaccesskey now_token npm_api_key
npm_api_token npm_auth_token npm_password npm_secret_key npm_token nuget_api_key
nuget_apikey nuget_key oauth_token object_storage_password octest_app_password
okta_client_token okta_oauth2_client_secret okta_oauth2_clientsecret omise_key
omise_skey onesignal_api_key onesignal_user_auth_key open_whisk_key openwhisk_key
org_gradle_project_sonatype_nexus_password ossrh_jira_password ossrh_password
ossrh_pass ossrh_secret packagecloud_token pagerduty_apikey parse_js_key
passwordtravis paypal_client_secret percy_token personal_key personal_secret
places_api_key places_apikey plotly_apikey plugin_password postgresql_pass
private_signing_password prod_access_key_id prod_password prod_secret_key
pushover_token pypi_passowrd quip_token rabbitmq_password refresh_token
registry_pass registry_secure release_gh_token release_token repotoken rest_api_key
rinkeby_private_key ropsten_private_key route53_access_key_id rubygems_auth_token
s3_access_key s3_access_key_id s3_key s3_secret_key s3_user_secret salesforce_bulk_test_password
sandbox_access_token sandbox_aws_access_key_id sandbox_aws_secret_access_key
sauce_access_key secret_key_base secretaccesskey secretkey segment_api_key
sendgrid_api_key sendgrid_key sendgrid_password sendgrid_user sendgrid_username
sendwithus_key sentry_auth_token sentry_key sentry_secret service_account_secret
ses_access_key ses_secret_key signing_key signing_key_password signing_key_secret
signing_key_sid slash_developer_space_key snoowrap_client_secret snoowrap_password
snoowrap_refresh_token snyk_api_token snyk_token socrata_app_token socrata_password
sonar_token sonatype_gpg_passphrase sonatype_nexus_password sonatype_pass
sonatype_password sonatype_token_password sonatype_token_user sonatypepassword
soundcloud_client_secret soundcloud_password spaces_access_key_id spaces_secret_access_key
spotify_api_access_token spotify_api_client_secret spring_mail_password sqsaccesskey
sqssecretkey square_reader_sdk_repository_password srcclr_api_token sshpass
star_test_aws_access_key_id star_test_secret_access_key starship_account_sid
starship_auth_token stormpath_api_key_id stormpath_api_key_secret strip_publishable_key
strip_secret_key stripe_private stripe_public surge_login surge_token svn_pass
tesco_api_key test_github_token travis_access_token travis_api_token travis_com_token
travis_e2e_token travis_gh_token travis_token twilio_api_key twilio_api_secret
twilio_sid twilio_token twine_password twitter_consumer_key twitter_consumer_secret
twitteroauthaccesssecret twitteroauthaccesstoken unity_password unity_serial
urban_key urban_master_secret urban_secret user_assets_access_key_id
user_assets_secret_access_key v_sfdc_client_secret v_sfdc_password virustotal_apikey
visual_recognition_api_key vscetoken wakatime_api_key watson_conversation_password
watson_device_password watson_password widget_basic_password widget_fb_password
wincert_password wordpress_db_password wpt_db_password wpt_report_api_key
wpt_ssh_private_key_base64 yangshun_gh_password yangshun_gh_token yt_account_client_secret
yt_account_refresh_token yt_api_key yt_client_secret yt_partner_client_secret
yt_partner_refresh_token yt_server_api_key zensonatypepassword zhuliang_gh_token
zopim_account_key
""".split()


def keyword_pattern(name: str) -> str:
    parts = [re.escape(p) for p in name.split("_")]
    return KEYWORD_TEMPLATE.replace("{name}", r"[_-]?".join(parts))


def build_patterns(extra=None, pattern_file=None):
    """Return a list of (compiled_regex, is_extra)."""
    compiled = []
    sources = list(FIXED_PATTERNS) + [keyword_pattern(n) for n in KEYWORD_NAMES]
    for src in sources:
        try:
            compiled.append((re.compile(src), False))
        except re.error:
            continue  # skip anything Python's re can't compile

    extras = []
    if extra:
        extras.append(extra)
    if pattern_file:
        with open(pattern_file, encoding="utf-8") as fh:
            extras.extend(l.strip() for l in fh if l.strip() and not l.startswith("#"))
    for src in extras:
        try:
            compiled.append((re.compile(src), True))
        except re.error as exc:
            print(f"{RED}[-]{WHITE} Invalid extra pattern {src!r}: {exc}{RESET}", file=sys.stderr)
            sys.exit(1)
    return compiled


# ----------------------------------------------------------------------------
# Scanner
# ----------------------------------------------------------------------------
class Scanner:
    def __init__(self, patterns, user_agent, cookies, detailed, find_all, timeout, verify_tls):
        self.patterns = patterns
        self.user_agent = user_agent
        self.cookies = cookies
        self.detailed = detailed
        self.find_all = find_all
        self.timeout = timeout
        self.seen = set()
        self.lock = threading.Lock()  # guards `seen` and stdout
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def say(self, text):
        with self.lock:
            print(text, flush=True)

    def fetch(self, url):
        headers = {"User-Agent": self.user_agent}
        if self.cookies:
            headers["Cookie"] = self.cookies
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def scan(self, url):
        if "http" not in url:
            self.say(f"{RED}[-]{WHITE} Skipping {url!r}: each URL must contain 'http'.{RESET}")
            return

        if self.detailed:
            self.say(f"{YELLOW}[*]{WHITE} Processing URL: {url}{RESET}")

        try:
            body = self.fetch(url)
        except Exception:
            self.say(f"{RED}[-]{WHITE} Unable to make a request for {url}{RESET}")
            return

        lines = None
        for regex, is_extra in self.patterns:
            if self.find_all:
                found = [m.group(0) for m in regex.finditer(body)]
            else:
                m = regex.search(body)
                found = [m.group(0)] if m else []

            for secret in found:
                with self.lock:
                    if secret in self.seen:
                        continue
                    self.seen.add(secret)

                if self.detailed:
                    if lines is None:
                        lines = body.split("\n")
                    for i, line in enumerate(lines, 1):
                        if secret in line:
                            self.say(
                                f"{GREEN}[+]{WHITE} {url} {GREEN}[{WHITE}{secret}{GREEN}] "
                                f"[{WHITE}Line: {i}{GREEN}]{RESET}"
                            )
                elif is_extra:
                    self.say(
                        f"{GREEN}[+]{WHITE} {url} {GREEN}[{WHITE}{secret}{GREEN}]"
                        f"{WHITE} -- Extra pattern detected! --{RESET}"
                    )
                else:
                    self.say(f"{BGREEN}[+]{WHITE} {url} {BGREEN}[{WHITE}{secret}{BGREEN}]{RESET}")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Hunt for API key leaks in JS files and pages. URLs are read from stdin.",
        epilog="example: cat js.txt | python3 mantra.py -t 100 -d",
    )
    ap.add_argument("-s", action="store_true", help="silent (no banner)")
    ap.add_argument("-t", type=int, default=50, metavar="N", help="thread number (default 50)")
    ap.add_argument("-ua", default="Mantra", help="User-Agent (default Mantra)")
    ap.add_argument("-d", action="store_true", help="detailed output (line numbers)")
    ap.add_argument("-c", default="", metavar="COOKIES", help="cookies, sent as the Cookie header")
    ap.add_argument("-ep", default="", metavar="REGEX", help="extra custom regex pattern")
    ap.add_argument("-pf", default="", metavar="FILE", help="file with extra regex patterns, one per line")
    ap.add_argument("-a", action="store_true", help="report every match per pattern, not just the first")
    ap.add_argument("-timeout", type=float, default=15.0, help="request timeout in seconds (default 15)")
    ap.add_argument("-verify", action="store_true", help="verify TLS certificates (off by default, like the original)")
    args = ap.parse_args()

    if not args.s:
        print(BANNER)

    patterns = build_patterns(args.ep or None, args.pf or None)
    scanner = Scanner(patterns, args.ua, args.c, args.d, args.a, args.timeout, args.verify)

    if sys.stdin.isatty():
        print(f"{RED}[-]{WHITE} Send URLs via stdin (ex: cat js.txt | python3 mantra.py){RESET}")
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=max(1, args.t)) as pool:
        for line in sys.stdin:
            url = line.strip()
            if url:
                pool.submit(scanner.scan, url)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
