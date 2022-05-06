// SPDX-License-Identifier: Apache-2.0

package yarn

type dependency struct {
	Name         string
	PkPath       string
	Version      string
	Resolved     string
	Integrity    string
	Dependencies []string
}

type dependencyV2 struct {
	Name         string
	Version      string            `yaml: "version"`
	Resolution   string            `yaml: "resolution"`
	Dependencies map[string]string `yaml: "dependencies"`
	Checksum     string            `yaml: "checksum"`
	LanguageName string            `yaml: "languageName"`
	LinkType     string            `yaml: "linkType:`
}

type yarnV2 = map[string]dependencyV2
