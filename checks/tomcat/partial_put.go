package tomcat

// CVE-2025-24813 needs Tomcat to accept a partial PUT (a PUT with a Content-Range),
// which makes Tomcat buffer the upload into a temporary file. Actively probing
// this writes a file server-side — a state change outside the detection-only,
// non-destructive scope — so it is never sent by default. It is reported as an
// unverified prerequisite, which is why a writable DefaultServlet reaches only
// `likely`, not `confirmed`.
const partialPUTStatus = "not attempted (a partial PUT writes a temp file server-side — outside non-destructive scope)"
