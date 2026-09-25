#!/bin/bash
# Recreate the WildFly management two-state regression lab (run on the Docker host).
# Probe from INSIDE the host/WSL: Docker-Desktop Windows->WSL port forwarding is
# flaky, the container itself is stable.
set -e
docker rm -f gopoc-wildfly >/dev/null 2>&1 || true
docker run -d --name gopoc-wildfly --restart=always -p 8088:8080 -p 9990:9990 \
  quay.io/wildfly/wildfly:latest \
  /opt/jboss/wildfly/bin/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0
echo "WildFly (SECURE mgmt) starting -> /management = 401 ManagementRealm = DETECTED"
echo
echo "To reach the OPEN state (=> LIKELY), after it has booted run:"
echo "  docker exec gopoc-wildfly sed -i 's/ http-authentication-factory=\"[^\"]*\"//' \\"
echo "    /opt/jboss/wildfly/standalone/configuration/standalone.xml"
echo "  docker restart gopoc-wildfly   # /management now 200 + product-version"
