#!/bin/bash
# Recreate the WebLogic T3/multi-protocol regression lab (run inside the vulhub host).
# vulhub CVE-2023-21839 = WebLogic 12.2.1.3 (HTTP + T3 on 7001).
# NOTE: WebLogic needs ~2 minutes to boot; on an unstable Docker engine it may not
# stay up. The deterministic cache regression is checks/weblogic TestSharedAssessmentCache.
set -e
VULHUB="${VULHUB:-/root/labs/vulhub}"
docker rm -f gopoc-weblogic >/dev/null 2>&1 || true
docker run -d --name gopoc-weblogic --restart=always -p 7001:7001 vulhub/weblogic:12.2.1.3-2018
echo "WebLogic starting on 7001 (wait ~2 min). Expect: CVE-2023-21839 LIKELY, CPU-2026-07 NOT_FOUND."
