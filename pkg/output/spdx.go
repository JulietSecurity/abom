package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/julietsecurity/abom/pkg/model"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx "github.com/spdx/tools-golang/spdx/v2/v2_3"

	spdxjson "github.com/spdx/tools-golang/json"
)

// SPDXFormatter outputs an ABOM as SPDX 2.3 JSON.
type SPDXFormatter struct{}

func NewSPDXFormatter() *SPDXFormatter {
	return &SPDXFormatter{}
}

func (f *SPDXFormatter) Format(abom *model.ABOM, w io.Writer) error {
	docName := "abom"
	if abom.Source.Target != "" {
		docName = "abom-" + sanitizeSPDXID(abom.Source.Target)
	}

	doc := &spdx.Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      docName,
		DocumentNamespace: fmt.Sprintf("https://spdx.org/spdxdocs/%s-%s", docName, uuid.New().String()),
		CreationInfo: &spdx.CreationInfo{
			Creators: []common.Creator{
				{CreatorType: "Tool", Creator: "abom-" + abom.Metadata.Version},
			},
			Created: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		},
	}

	// Root package for the source repo
	rootPkgID := common.ElementID("source-repo")
	rootPkg := &spdx.Package{
		PackageName:             abom.Source.Target,
		PackageSPDXIdentifier:   rootPkgID,
		PackageVersion:          abom.Source.Ref,
		PackageDownloadLocation: abom.Source.Target,
		FilesAnalyzed:           false,
	}
	doc.Packages = append(doc.Packages, rootPkg)

	// DESCRIBES relationship
	doc.Relationships = append(doc.Relationships, &spdx.Relationship{
		RefA:         common.MakeDocElementID("", "DOCUMENT"),
		RefB:         common.MakeDocElementID("", string(rootPkgID)),
		Relationship: "DESCRIBES",
	})

	// Process actions
	seen := make(map[string]bool)

	for _, wf := range abom.Workflows {
		for _, job := range wf.Jobs {
			for _, step := range job.Steps {
				if step.Action == nil {
					continue
				}
				pkgID := addSPDXPackage(doc, step.Action, seen)
				// Root DEPENDS_ON direct actions
				doc.Relationships = append(doc.Relationships, &spdx.Relationship{
					RefA:         common.MakeDocElementID("", string(rootPkgID)),
					RefB:         common.MakeDocElementID("", string(pkgID)),
					Relationship: "DEPENDS_ON",
				})
			}
		}
	}

	return spdxjson.Write(doc, w, spdxjson.Indent("  "))
}

func addSPDXPackage(doc *spdx.Document, ref *model.ActionRef, seen map[string]bool) common.ElementID {
	pkgID := spdxElementID(ref)

	if seen[string(pkgID)] {
		return pkgID
	}
	seen[string(pkgID)] = true

	pkg := &spdx.Package{
		PackageName:             componentName(ref),
		PackageSPDXIdentifier:   pkgID,
		PackageVersion:          ref.Ref,
		PackageDownloadLocation: packageDownloadLocation(ref),
		FilesAnalyzed:           false,
	}

	// PURL external reference
	if purl := actionPURL(ref); purl != "" {
		pkg.PackageExternalReferences = append(pkg.PackageExternalReferences, &spdx.PackageExternalReference{
			Category: "PACKAGE-MANAGER",
			RefType:  "purl",
			Locator:  purl,
		})
	}

	// Security external reference for compromised actions
	if ref.Compromised && ref.Advisory != "" {
		pkg.PackageExternalReferences = append(pkg.PackageExternalReferences, &spdx.PackageExternalReference{
			Category: "SECURITY",
			RefType:  "advisory",
			Locator:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", ref.Advisory),
		})
	}

	doc.Packages = append(doc.Packages, pkg)

	// Transitive dependencies
	for _, dep := range ref.Dependencies {
		depID := addSPDXPackage(doc, dep, seen)
		doc.Relationships = append(doc.Relationships, &spdx.Relationship{
			RefA:         common.MakeDocElementID("", string(pkgID)),
			RefB:         common.MakeDocElementID("", string(depID)),
			Relationship: "DEPENDS_ON",
		})
	}

	return pkgID
}

func spdxElementID(ref *model.ActionRef) common.ElementID {
	switch ref.ActionType {
	case model.ActionTypeDocker:
		return common.ElementID("docker-" + sanitizeSPDXID(ref.Path))
	case model.ActionTypeLocal:
		return common.ElementID("local-" + sanitizeSPDXID(ref.Path))
	default:
		return common.ElementID(sanitizeSPDXID(fmt.Sprintf("%s-%s-%s", ref.Owner, ref.Repo, ref.Ref)))
	}
}

func sanitizeSPDXID(s string) string {
	replacer := strings.NewReplacer(
		"/", "-",
		"@", "-",
		".", "-",
		":", "-",
		" ", "-",
	)
	return replacer.Replace(s)
}

func packageDownloadLocation(ref *model.ActionRef) string {
	if ref.Owner != "" && ref.Repo != "" {
		return fmt.Sprintf("https://github.com/%s/%s", ref.Owner, ref.Repo)
	}
	return "NOASSERTION"
}
