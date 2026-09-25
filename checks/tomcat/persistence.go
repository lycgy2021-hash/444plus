package tomcat

// The RCE path of CVE-2025-24813 also requires file-backed session persistence
// (a PersistentManager with a FileStore) and a deserialization gadget on the
// classpath. Neither is remotely observable without exploitation, so both are
// reported as unknown prerequisites. Their absence is why this checker never
// returns confirmed even when the DefaultServlet is writable.
const (
	persistenceStatus = "unknown (file-backed session persistence is not remotely observable)"
	gadgetStatus      = "unknown (a usable deserialization gadget on the classpath is not remotely observable)"
)
