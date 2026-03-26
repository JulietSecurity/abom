package output

import (
	"encoding/json"
	"io"

	"github.com/julietsecurity/abom/pkg/model"
)

// JSONFormatter outputs an ABOM as native JSON.
type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

func (f *JSONFormatter) Format(abom *model.ABOM, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(abom)
}
