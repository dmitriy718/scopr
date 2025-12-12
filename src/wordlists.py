"""
Wordlist Management Module
Handles built-in wordlists and custom wordlist loading for endpoint discovery.
"""

import os
from typing import List, Set
from pathlib import Path


COMMON_DIRECTORIES = [
    "", "admin", "api", "app", "assets", "backup", "backups", "bin", "blog",
    "cache", "cgi-bin", "classes", "cms", "common", "components", "config",
    "configuration", "content", "controller", "controllers", "core", "css",
    "data", "database", "db", "debug", "demo", "dev", "development", "docs",
    "documentation", "download", "downloads", "editor", "email", "error",
    "errors", "example", "examples", "export", "feed", "feeds", "file",
    "files", "fonts", "forms", "forum", "ftp", "gallery", "graph", "graphs",
    "help", "hidden", "home", "html", "http", "images", "img", "import",
    "inc", "include", "includes", "index", "install", "internal", "js",
    "json", "lab", "lang", "lib", "libraries", "library", "license", "log",
    "login", "logout", "logs", "mail", "main", "manage", "management",
    "manager", "media", "member", "members", "misc", "mobile", "model",
    "models", "module", "modules", "new", "news", "old", "order", "orders",
    "page", "pages", "panel", "password", "php", "phpmyadmin", "plugin",
    "plugins", "portal", "post", "posts", "print", "private", "profile",
    "public", "register", "reports", "resource", "resources", "rest", "rss",
    "scripts", "search", "secure", "security", "server", "service", "services",
    "session", "settings", "setup", "shop", "site", "sites", "source", "sql",
    "src", "static", "stats", "status", "storage", "store", "style", "styles",
    "system", "temp", "template", "templates", "test", "testing", "tests",
    "theme", "themes", "tmp", "tool", "tools", "upload", "uploads", "user",
    "users", "util", "utilities", "utility", "utils", "var", "vendor",
    "video", "videos", "view", "views", "web", "webmail", "wp-admin",
    "wp-content", "wp-includes", "xml", "xmlrpc"
]


API_ENDPOINTS = [
    "api", "api/v1", "api/v2", "api/v3", "api/auth", "api/login", "api/logout",
    "api/user", "api/users", "api/admin", "api/data", "api/search", "api/status",
    "api/health", "api/info", "api/config", "api/settings", "api/docs",
    "api/swagger", "api/graphql", "graphql", "rest", "rest/api", "v1", "v2",
    "v3", "oauth", "oauth2", "auth", "authenticate", "token", "tokens",
    "webhook", "webhooks", "callback", "endpoints", "service", "services"
]


HIDDEN_PATHS = [
    ".git", ".git/config", ".git/HEAD", ".gitignore", ".htaccess", ".htpasswd",
    ".env", ".env.local", ".env.production", ".env.development", ".env.backup",
    ".svn", ".svn/entries", ".hg", ".bzr", ".DS_Store", ".well-known",
    ".well-known/security.txt", "security.txt", "humans.txt", "crossdomain.xml",
    "clientaccesspolicy.xml", "WEB-INF", "WEB-INF/web.xml", "META-INF",
    "META-INF/MANIFEST.MF", "composer.json", "composer.lock", "package.json",
    "package-lock.json", "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt",
    "Pipfile", "Pipfile.lock", "Dockerfile", "docker-compose.yml", ".dockerignore",
    "Makefile", "Rakefile", "Gruntfile.js", "gulpfile.js", "webpack.config.js",
    "tsconfig.json", ".babelrc", ".eslintrc", ".prettierrc", "phpinfo.php",
    "info.php", "test.php", "debug.php", "server-status", "server-info"
]


COMMON_FILES = [
    "index.html", "index.htm", "index.php", "index.asp", "index.aspx",
    "index.jsp", "default.html", "default.htm", "default.asp", "default.aspx",
    "home.html", "home.php", "main.html", "main.php", "login.html", "login.php",
    "admin.html", "admin.php", "config.php", "config.inc.php", "configuration.php",
    "settings.php", "database.php", "db.php", "connect.php", "connection.php",
    "readme.txt", "README.md", "README.txt", "CHANGELOG.md", "CHANGELOG.txt",
    "LICENSE", "LICENSE.txt", "license.txt", "robots.txt", "sitemap.xml",
    "sitemap_index.xml", "rss.xml", "feed.xml", "atom.xml", "favicon.ico",
    "crossdomain.xml", "manifest.json", "sw.js", "service-worker.js"
]


BACKUP_FILES = [
    "backup.sql", "backup.zip", "backup.tar.gz", "backup.tar", "database.sql",
    "db.sql", "dump.sql", "data.sql", "site.zip", "www.zip", "web.zip",
    "public.zip", "html.zip", "backup.bak", "old.zip", "archive.zip",
    "1.zip", "2.zip", "backup1.zip", "backup2.zip"
]


PARAMETER_WORDLIST = [
    "id", "page", "p", "q", "s", "search", "query", "keyword", "keywords",
    "user", "username", "name", "email", "pass", "password", "token", "key",
    "api_key", "apikey", "secret", "auth", "session", "sid", "uid", "pid",
    "cat", "category", "type", "sort", "order", "limit", "offset", "start",
    "end", "from", "to", "date", "year", "month", "day", "file", "path",
    "dir", "folder", "url", "link", "redirect", "return", "next", "prev",
    "callback", "format", "output", "lang", "language", "locale", "debug",
    "test", "admin", "action", "do", "cmd", "command", "module", "view",
    "template", "theme", "style", "mode", "status", "state", "filter",
    "include", "load", "read", "write", "download", "upload", "delete",
    "remove", "add", "create", "update", "edit", "save", "submit"
]


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "admin", "api",
    "app", "apps", "auth", "beta", "blog", "cdn", "cloud", "cms", "cpanel",
    "dashboard", "demo", "dev", "developer", "docs", "download", "forum",
    "gateway", "git", "gitlab", "graphql", "help", "home", "host", "image",
    "images", "img", "internal", "intranet", "jenkins", "jira", "kb", "legacy",
    "lib", "login", "m", "mobile", "monitor", "mysql", "new", "news", "old",
    "panel", "portal", "preview", "prod", "production", "proxy", "public",
    "qa", "redis", "remote", "repo", "repository", "rest", "sandbox", "search",
    "secure", "server", "service", "services", "shop", "signin", "signup",
    "sso", "stage", "staging", "static", "status", "store", "support", "sync",
    "sysadmin", "system", "test", "testing", "tools", "update", "upload",
    "vpn", "web", "webdisk", "weblog", "wiki", "ws", "www1", "www2", "www3"
]


class WordlistManager:
    """Manages wordlists for endpoint discovery scanning."""

    def __init__(self, wordlist_dir: str = "wordlists"):
        """
        Initialize the wordlist manager.
        
        Args:
            wordlist_dir: Directory containing custom wordlist files
        """
        self.wordlist_dir = Path(wordlist_dir)
        self.wordlist_dir.mkdir(exist_ok=True)

    def get_builtin_wordlist(self, category: str = "all") -> List[str]:
        """
        Get a built-in wordlist by category.
        
        Args:
            category: One of 'directories', 'api', 'hidden', 'files', 
                     'backup', 'parameters', 'subdomains', or 'all'
                     
        Returns:
            List of paths/names for the requested category
        """
        wordlists = {
            "directories": COMMON_DIRECTORIES,
            "api": API_ENDPOINTS,
            "hidden": HIDDEN_PATHS,
            "files": COMMON_FILES,
            "backup": BACKUP_FILES,
            "parameters": PARAMETER_WORDLIST,
            "subdomains": COMMON_SUBDOMAINS
        }

        if category == "all":
            all_paths = set()
            for key in ["directories", "api", "hidden", "files", "backup"]:
                all_paths.update(wordlists[key])
            return sorted(list(all_paths))
        
        return wordlists.get(category, [])

    def load_custom_wordlist(self, filename: str) -> List[str]:
        """
        Load a custom wordlist from file.
        
        Args:
            filename: Name of the wordlist file
            
        Returns:
            List of paths from the wordlist
        """
        filepath = self.wordlist_dir / filename
        if not filepath.exists():
            raise FileNotFoundError(f"Wordlist not found: {filename}")

        words = set()
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith('#'):
                    words.add(word)
        
        return sorted(list(words))

    def save_custom_wordlist(self, filename: str, words: List[str]) -> str:
        """
        Save a custom wordlist to file.
        
        Args:
            filename: Name of the wordlist file
            words: List of words to save
            
        Returns:
            Path to the saved file
        """
        filepath = self.wordlist_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            for word in sorted(set(words)):
                f.write(f"{word}\n")
        
        return str(filepath)

    def list_custom_wordlists(self) -> List[str]:
        """
        List available custom wordlist files.
        
        Returns:
            List of wordlist filenames
        """
        if not self.wordlist_dir.exists():
            return []
        
        return [f.name for f in self.wordlist_dir.iterdir() 
                if f.is_file() and f.suffix in ('.txt', '.lst', '')]

    def merge_wordlists(self, *wordlists: List[str]) -> List[str]:
        """
        Merge multiple wordlists into one deduplicated list.
        
        Args:
            *wordlists: Variable number of wordlist lists
            
        Returns:
            Merged and deduplicated list
        """
        merged = set()
        for wordlist in wordlists:
            merged.update(wordlist)
        return sorted(list(merged))

    def generate_urls(self, base_url: str, paths: List[str]) -> List[str]:
        """
        Generate full URLs from a base URL and list of paths.
        
        Args:
            base_url: The base URL (e.g., https://example.com)
            paths: List of paths to append
            
        Returns:
            List of full URLs
        """
        from urllib.parse import urljoin
        
        base_url = base_url.rstrip('/')
        urls = set()
        
        for path in paths:
            path = path.lstrip('/')
            url = f"{base_url}/{path}"
            urls.add(url)
            
            if not path.endswith('/') and '.' not in path.split('/')[-1]:
                urls.add(f"{url}/")
        
        return sorted(list(urls))

    def get_recursive_paths(self, base_paths: List[str], depth: int = 2) -> List[str]:
        """
        Generate recursive paths by combining base paths.
        
        Args:
            base_paths: List of base directory paths
            depth: How deep to recurse (default 2)
            
        Returns:
            List of combined paths
        """
        if depth <= 1:
            return base_paths

        result = set(base_paths)
        current_level = list(base_paths)

        for _ in range(depth - 1):
            next_level = []
            for base in current_level:
                if base and not base.endswith(('.php', '.html', '.js', '.css', '.txt')):
                    for path in base_paths[:50]:
                        if path and path != base:
                            combined = f"{base.rstrip('/')}/{path.lstrip('/')}"
                            if combined not in result:
                                result.add(combined)
                                next_level.append(combined)
            current_level = next_level[:1000]

        return sorted(list(result))


def get_default_wordlist() -> List[str]:
    """Get the default combined wordlist for scanning."""
    manager = WordlistManager()
    return manager.get_builtin_wordlist("all")
