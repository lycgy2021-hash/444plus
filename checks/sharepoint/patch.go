package sharepoint

import "regexp"

// SPBuild is a SharePoint build: 16.0.<build>.<revision>.
type SPBuild [4]int

func lessBuild(a, b SPBuild) bool {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// buildRE matches the significant build in a MicrosoftSharePointTeamServices
// header or page (e.g. "16.0.10417.20037"). The header can also read
// "16.0.0.<build>"; that form lacks a revision and is treated as unknown.
var buildRE = regexp.MustCompile(`16\.0\.([1-9][0-9]{3,})\.([0-9]+)`)

func parseBuild(s string) (SPBuild, bool) {
	m := buildRE.FindStringSubmatch(s)
	if m == nil {
		return SPBuild{}, false
	}
	var a, b int
	for _, c := range m[1] {
		a = a*10 + int(c-'0')
	}
	for _, c := range m[2] {
		b = b*10 + int(c-'0')
	}
	return SPBuild{16, 0, a, b}, true
}

// line classifies a build into its SharePoint product line by the build major.
func line(b SPBuild) string {
	switch {
	case b[2] >= 4000 && b[2] < 6000:
		return "2016"
	case b[2] >= 10000 && b[2] < 11000:
		return "2019"
	case b[2] >= 17000 && b[2] < 19000:
		return "SE"
	default:
		return ""
	}
}

// fixed holds the ToolShell family fully-patched build per line (July 2025,
// CVE-2025-53770/53771 fix, which supersedes the CVE-2025-49704/49706 fix).
var fixed = map[string]SPBuild{
	"2016": {16, 0, 5513, 1001},   // KB5002760
	"2019": {16, 0, 10417, 20037}, // KB5002754
	"SE":   {16, 0, 18526, 20508}, // KB5002768
}

// affectedBuild reports whether a build predates the ToolShell fix for its line.
func affectedBuild(b SPBuild) (affected bool, ln string, fix SPBuild) {
	ln = line(b)
	if ln == "" {
		return false, "", SPBuild{}
	}
	fix = fixed[ln]
	return lessBuild(b, fix), ln, fix
}
