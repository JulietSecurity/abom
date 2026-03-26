package advisory

import _ "embed"

//go:embed builtin_advisories.json
var builtinData []byte
