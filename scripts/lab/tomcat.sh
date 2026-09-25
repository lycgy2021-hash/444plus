#!/bin/bash
# Recreate the Tomcat 3-state regression lab (run inside the vulhub host, e.g. WSL).
# vulhub CVE-2025-24813 = Tomcat 9.0.97 with a writable DefaultServlet + FileStore.
set -e
cd "$(dirname "$0")"

VULHUB="${VULHUB:-/root/labs/vulhub}"

echo "== building vulhub Tomcat 9.0.97 (writable) =="
( cd "$VULHUB/tomcat/CVE-2025-24813" && docker compose build )

docker rm -f gopoc-tomcat-vuln gopoc-tomcat-ro gopoc-tomcat-fixed >/dev/null 2>&1 || true
docker run -d --name gopoc-tomcat-vuln  --restart=always -p 8180:8080 cve-2025-24813-tomcat   # writable  -> LIKELY
docker run -d --name gopoc-tomcat-ro    --restart=always -p 8181:8080 vulhub/tomcat:9.0.97    # readonly  -> DETECTED
docker run -d --name gopoc-tomcat-fixed --restart=always -p 8182:8080 tomcat:9.0.99           # fixed     -> NOT_FOUND
echo "Tomcat lab up on 8180 (writable) / 8181 (readonly) / 8182 (fixed)"
