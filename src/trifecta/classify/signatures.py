"""Signature rules mapping code signals to A / B / C capability legs.

Each leg has three signal sources with different precision:

  * ``callee``  -- functions/attributes the implementation actually calls
                   (e.g. ``requests.post``, ``os.environ``). Strongest signal.
  * ``name``    -- the tool's own name (``send_email``, ``read_file``).
  * ``desc``    -- words in the tool description / schema fields. Weakest, so
                   it carries the lowest confidence and never fires alone for a
                   ``confirmed`` upgrade.

Patterns are matched as lowercased substrings, which keeps the table small
while tolerating naming variation (``get_secret`` matches ``secret``).
"""

from __future__ import annotations

from ..ir import LEG_EGRESS, LEG_INGRESS, LEG_PRIVATE

# confidence by signal source
CONF = {"callee": 0.9, "name": 0.85, "desc": 0.6}

RULES: dict[str, dict[str, list[str]]] = {
    LEG_INGRESS: {
        "callee": [
            "requests.get", "requests.request", "httpx.get", "httpx.request",
            "urllib.request.urlopen", "urlopen", "aiohttp", "feedparser.parse",
            "imaplib", "gmail", "playwright", "selenium", "beautifulsoup", "bs4",
        ],
        "name": [
            "web_fetch", "fetch_url", "load_url", "read_url", "browse", "crawl",
            "scrape", "search_web", "web_search", "read_email", "get_email",
            "read_inbox", "fetch_webpage", "download",
        ],
        "desc": [
            "fetch a url", "fetch the url", "browse", "web page", "webpage",
            "crawl", "scrape", "read email", "inbox", "external content",
            "untrusted", "user-supplied", "user supplied", "from the internet",
            "search the web", "third-party", "uploaded file",
        ],
    },
    LEG_PRIVATE: {
        "callee": [
            "os.environ", "os.getenv", "getenv", "open", "pathlib", "glob.glob",
            "sqlite3.connect", "cursor.execute", "psycopg2", "pymysql",
            "sqlalchemy", "redis", "boto3.client", "vault", "keyring",
            "read_text", "read_bytes",
        ],
        "name": [
            "read_file", "load_file", "get_file", "query_db", "query_database",
            "run_sql", "execute_sql", "get_secret", "read_secret", "get_env",
            "get_credential", "get_api_key", "internal_api", "lookup_customer",
            "get_user_record",
        ],
        "desc": [
            "read a file", "filesystem", "file system", "local file",
            "environment variable", "secret", "credential", "api key",
            "password", "private", "internal database", "query the database",
            "internal api", "customer record", "from the database",
        ],
    },
    LEG_EGRESS: {
        "callee": [
            "requests.post", "requests.put", "requests.patch", "requests.delete",
            "httpx.post", "httpx.put", "smtplib", "sendmail", "send_message",
            "boto3", "s3.put_object", "upload_file", "slack_sdk", "git.push",
            "subprocess.run", "subprocess.popen", "webhook",
        ],
        "name": [
            "http_post", "post_webhook", "send_webhook", "send_email",
            "send_mail", "send_message", "upload", "publish", "git_push",
            "notify", "export_to", "post_to",
        ],
        "desc": [
            "send an email", "send email", "post to", "http post", "webhook",
            "upload to", "publish to", "push to", "send a message to",
            "exfiltrate", "external endpoint", "external url", "remote server",
            "send the data", "forward to",
        ],
    },
}
