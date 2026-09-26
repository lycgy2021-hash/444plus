#!/bin/bash
# Recreate the Jenkins two-line regression lab (run on the Docker host).
# Probe from INSIDE the container (docker exec ... /tmp/gopoc): Docker-Desktop
# Windows->WSL port forwarding is flaky, the containers themselves are stable.
#
# Two containers cover all four acceptance scenarios:
#   A) 2.568.3 unsecured  -> Script Console OPEN  -> MISCONFIG likely; CVE not_found (fixed)
#   B) 2.426.2 secure     -> Script Console 403   -> MISCONFIG detected; CVE likely (affected + CLI)
set -e

docker rm -f gopoc-jenkins gopoc-jenkins-cve >/dev/null 2>&1 || true

# A) Modern Jenkins with the setup wizard OFF => no security realm => Script
#    Console reachable anonymously (the misconfiguration state).
docker run -d --name gopoc-jenkins --restart=always -p 8380:8080 -p 50000:50000 \
  -e JAVA_OPTS="-Djenkins.install.runSetupWizard=false" \
  jenkins/jenkins:lts
echo "A) gopoc-jenkins (2.x LTS, OPEN Script Console) -> MISCONFIG likely, CVE not_found"

# B) An affected LTS in its secure default (setup wizard on => everything 403).
docker run -d --name gopoc-jenkins-cve --restart=always -p 8480:8080 \
  jenkins/jenkins:2.426.2
echo "B) gopoc-jenkins-cve (2.426.2, SECURE) -> MISCONFIG detected, CVE-2024-23897 likely"

echo
echo "After both boot (wait for /script to answer), scan from inside each container:"
echo "  docker cp <gopoc-linux-binary> gopoc-jenkins:/tmp/gopoc"
echo "  docker exec gopoc-jenkins     /tmp/gopoc scan http://localhost:8080 --discover"
echo "  docker exec gopoc-jenkins-cve /tmp/gopoc scan http://localhost:8080 --discover"
