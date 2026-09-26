// Package checks is the composition root for trusted, compiled checkers.
// Add new registrations here; the engine does not need to change.
package checks

import (
	"gopoc/checks/apache"
	"gopoc/checks/fortinet"
	"gopoc/checks/gitlab"
	"gopoc/checks/ingressnginx"
	"gopoc/checks/jbosswildfly"
	"gopoc/checks/jenkins"
	"gopoc/checks/netscaler"
	"gopoc/checks/nginx"
	"gopoc/checks/nginxui"
	"gopoc/checks/oracleproxy"
	"gopoc/checks/sharepoint"
	"gopoc/checks/tomcat"
	"gopoc/checks/weblogic"
	"gopoc/internal/httpx"
	"gopoc/internal/model"
	"gopoc/internal/registry"
)

func Builtin(client httpx.Probe, mode model.Mode, canary model.CanaryConfig) (*registry.Registry, error) {
	r := registry.New()
	for _, c := range []model.Checker{
		apache.NewCVE202141773(client, mode, canary), apache.NewCVE202142013(client, mode, canary),
		nginx.NewCVE202642533(client), nginxui.NewCVE202642238(client, mode), ingressnginx.NewCVE20251974(client, mode),
		fortinet.NewCVE202455591(client), fortinet.NewCVE202524472(client), fortinet.NewCVE202532756(client),
		sharepoint.NewCVE202549704(client), sharepoint.NewCVE202549706(client), sharepoint.NewCVE202553770(client), sharepoint.NewCVE202553771(client),
		tomcat.NewCVE202524813(client),
		weblogic.NewCVE202321839(client),
		weblogic.NewCVE202660199(client), weblogic.NewCVE202660291(client), weblogic.NewCVE202660292(client),
		weblogic.NewCVE202660200(client), weblogic.NewCVE202660294(client),
		weblogic.NewCVE202660198(client), weblogic.NewCVE202660202(client),
		oracleproxy.NewCVE202621962(client), oracleproxy.NewCVE202660364(client),
		netscaler.NewCVE20257775(client), netscaler.NewCVE20256543(client),
		jbosswildfly.NewUnauthenticatedManagement(client),
		jenkins.NewAnonScriptConsole(client), jenkins.NewCVE202423897(client),
		gitlab.NewCVE20237028(client), gitlab.NewCVE20232825(client),
	} {
		if err := r.Register(c); err != nil {
			return nil, err
		}
	}
	return r, nil
}
