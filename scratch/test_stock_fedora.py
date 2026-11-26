import sys, re, tempfile, subprocess
from pathlib import Path
sys.path.insert(0, '/home/euripedes/astral/astral-ad-dns/samba-ad-dc')
import ad_operations

fedora_stock = """//
// named.conf
//
// Provided by Red Hat bind package to configure the ISC BIND named(8) DNS
// server as a caching only nameserver (as a localhost DNS resolver only).
//
// See /usr/share/doc/bind*/sample/ for example named configuration files.
//

options {
        listen-on port 53 { 127.0.0.1; };
        listen-on-v6 port 53 { ::1; };
        directory       "/var/named";
        dump-file       "/var/named/data/cache_dump.db";
        statistics-file "/var/named/data/named_stats.txt";
        memstatistics-file "/var/named/data/named_mem_stats.txt";
        secroots-file   "/var/named/data/named.secroots";
        recursing-file  "/var/named/data/named.recursing";
        allow-query     { localhost; };

        /*
         - If you are building an AUTHORITATIVE DNS server, do NOT enable recursion.
         - If you are building a RECURSIVE (caching) DNS server, you need to enable
           recursion.
         - If your recursive DNS server has a public IP address, you MUST enable access
           control to limit queries to your legitimate users. Failing to do so will
           cause your server to become part of large scale DNS amplification
           attacks. Implementing BCP38 within your network would greatly
           reduce such attack surface
        */
        recursion yes;

        dnssec-validation yes;

        managed-keys-directory "/var/named/dynamic";
        geoip-directory "/usr/share/GeoIP";

        pid-file "/run/named/named.pid";
        session-keyfile "/run/named/session.key";

        /* https://fedoraproject.org/wiki/Changes/CryptoPolicy */
        include "/etc/crypto-policies/back-ends/bind.config";
};

logging {
        channel default_debug {
                file "data/named.run";
                severity dynamic;
        };
};

zone "." IN {
        type hint;
        file "/etc/named.ca";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
"""

clean = re.sub(r'//[^\n]*|#[^\n]*|/\*.*?\*/', lambda m: ' ' * len(m[0]), fedora_stock, flags=re.S)
print("clean search include:", re.search(r'\binclude\b', clean))
if re.search(r'\binclude\b', clean):
    print("Found include inside clean! Where?")
    for m in re.finditer(r'\binclude\b', clean):
        print("  include at pos", m.start(), ":", repr(fedora_stock[m.start()-20:m.end()+40]))

try:
    c = ad_operations.replace_options(fedora_stock, ad_operations.hybrid_options(['8.8.8.8'], '/var/named', 5353))
    print("replace_options SUCCESS, len:", len(c))
except Exception as e:
    print("replace_options FAILED:", type(e).__name__, e)
print("\n=== GENERATED CONFIG ===\n")
print(c)
print("\n=== NAMED-CHECKCONF ON GENERATED CONFIG ===\n")
with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as tf:
    tf.write(c)
    tfname = tf.name
res = subprocess.run(['named-checkconf', tfname], capture_output=True, text=True)
print("Returncode:", res.returncode)
print("Stdout:", res.stdout)
print("Stderr:", res.stderr)
