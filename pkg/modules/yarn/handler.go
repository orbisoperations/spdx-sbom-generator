// SPDX-License-Identifier: Apache-2.0

package yarn

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	log "github.com/sirupsen/logrus"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
	"github.com/spdx/spdx-sbom-generator/pkg/reader"
)

type yarn struct {
	metadata models.PluginMetadata
}

var (
	errDependenciesNotFound = errors.New("unable to generate SPDX file, no modules founded. Please install them before running spdx-sbom-generator, e.g.: `yarn install`")
	yarnRegistry            = "https://registry.yarnpkg.com"
	lockFile                = "yarn.lock"
	rg                      = regexp.MustCompile(`^(((git|hg|svn|bzr)\+)?(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|ssh:\/\/|git:\/\/|svn:\/\/|sftp:\/\/|ftp:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+){0,100}\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*))|(git\+git@[a-zA-Z0-9\.]+:[a-zA-Z0-9/\\.@]+)|(bzr\+lp:[a-zA-Z0-9\.]+)$`)
)

// New creates a new yarn instance
func New() *yarn {
	return &yarn{
		metadata: models.PluginMetadata{
			Name:       "Yarn Package Manager",
			Slug:       "yarn",
			Manifest:   []string{"package.json", lockFile},
			ModulePath: []string{"node_modules"},
		},
	}
}

// GetMetadata returns metadata descriptions Name, Slug, Manifest, ModulePath
func (m *yarn) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// IsValid checks if module has a valid Manifest file
// for yarn manifest file is package.json
func (m *yarn) IsValid(path string) bool {
	for _, p := range m.metadata.Manifest {
		if !helper.Exists(filepath.Join(path, p)) {
			return false
		}
	}
	return true
}

// HasModulesInstalled checks if modules of manifest file already installed
func (m *yarn) HasModulesInstalled(path string) error {
	log.Info("Checking for installed modules")
	for _, p := range m.metadata.ModulePath {
		if !helper.Exists(filepath.Join(path, p)) {
			return errDependenciesNotFound
		}
	}

	for _, p := range m.metadata.Manifest {
		if !helper.Exists(filepath.Join(path, p)) {
			return errDependenciesNotFound
		}
	}
	return nil
}

// GetVersion returns yarn version
func (m *yarn) GetVersion() (string, error) {
	cmd := exec.Command("yarn", "-v")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	if len(strings.Split(string(output), ".")) != 3 {
		return "", fmt.Errorf("unexpected version format: %s", output)
	}

	return string(output), nil
}

// SetRootModule ...
func (m *yarn) SetRootModule(path string) error {
	return nil
}

// GetRootModule return
//root package information ex. Name, Version
func (m *yarn) GetRootModule(path string) (*models.Module, error) {
	r := reader.New(filepath.Join(path, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return &models.Module{}, err
	}
	mod := &models.Module{}

	if pkResult["name"] != nil {
		mod.Name = pkResult["name"].(string)
	}
	if pkResult["author"] != nil {
		mod.Supplier.Name = pkResult["author"].(string)
	}
	if pkResult["version"] != nil {
		mod.Version = pkResult["version"].(string)
	}
	repository := pkResult["repository"]
	if repository != nil {
		if rep, ok := repository.(string); ok {
			mod.PackageDownloadLocation = rep
		}
		if _, ok := repository.(map[string]interface{}); ok && repository.(map[string]interface{})["url"] != nil {
			mod.PackageDownloadLocation = repository.(map[string]interface{})["url"].(string)
		}
	}
	if pkResult["homepage"] != nil {
		mod.PackageURL = helper.RemoveURLProtocol(pkResult["homepage"].(string))
		mod.PackageDownloadLocation = mod.PackageURL
	}
	if !rg.MatchString(mod.PackageDownloadLocation) {
		mod.PackageDownloadLocation = "NONE"
	}
	mod.Modules = map[string]*models.Module{}
	mod.Copyright = getCopyright(path)
	modLic, err := helper.GetLicenses(path)
	if err != nil {
		log.Debug("error finding license file: %s\n", err.Error())
		return mod, nil
	}
	mod.LicenseDeclared = helper.BuildLicenseDeclared(modLic.ID)
	mod.LicenseConcluded = helper.BuildLicenseConcluded(modLic.ID)
	mod.CommentsLicense = modLic.Comments
	if !helper.LicenseSPDXExists(modLic.ID) {
		mod.OtherLicense = append(mod.OtherLicense, modLic)
	}
	return mod, nil
}

// ListUsedModules return brief info of installed modules, Name and Version
func (m *yarn) ListUsedModules(path string) ([]models.Module, error) {
	r := reader.New(filepath.Join(path, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return []models.Module{}, err
	}
	modules := make([]models.Module, 0)
	deps := pkResult["dependencies"].(map[string]interface{})

	for k, v := range deps {
		var mod models.Module
		mod.Name = k
		mod.Version = strings.TrimPrefix(v.(string), "^")
		modules = append(modules, mod)
	}

	return modules, nil
}

// ListModulesWithDeps return all info of installed modules
func (m *yarn) ListModulesWithDeps(path string) ([]models.Module, error) {
	yarnv2Deps, err := readLockV2File(filepath.Join(path, lockFile))
	if err != nil {
		log.Infof("error parsing yarn v2 lock file - defaulting to yarn v1\n")

		deps, err := readLockFile(filepath.Join(path, lockFile))
		allDeps := appendNestedDependencies(deps)
		if err != nil {
			return nil, err
		}

		return m.buildDependencies(path, allDeps)
	} else {
		log.Debug("creating dependencies based on yarn v2")
		allDeps, err := appendNestedDependenciesV2(yarnv2Deps)
		if err != nil {
			return nil, err
		}

		return buildDepenenciesV2(path, allDeps, m)
	}
}

func (m *yarn) buildDependencies(path string, deps []dependency) ([]models.Module, error) {
	modules := make([]models.Module, 0)
	de, err := m.GetRootModule(path)
	if err != nil {
		return modules, err
	}
	h := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%s", de.Name, de.Version))))
	de.CheckSum = &models.CheckSum{
		Algorithm: "SHA256",
		Value:     h,
	}
	de.Supplier.Name = de.Name
	if de.PackageDownloadLocation == "" {
		de.PackageDownloadLocation = de.Name
	}
	modules = append(modules, *de)
	for _, d := range deps {
		var mod models.Module
		mod.Name = d.Name
		mod.Version = extractVersion(d.Version)
		modules[0].Modules[d.Name] = &models.Module{
			Name:     d.Name,
			Version:  mod.Version,
			CheckSum: &models.CheckSum{Content: []byte(fmt.Sprintf("%s-%s", d.Name, mod.Version))},
		}
		if len(d.Dependencies) != 0 {
			mod.Modules = map[string]*models.Module{}
			for _, depD := range d.Dependencies {
				ar := strings.Split(strings.TrimSpace(depD), " ")
				name := strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(ar[0], "\""), "\""), "@")
				if name == "optionalDependencies:" {
					continue
				}

				version := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(ar[1]), "\""), "\"")
				if extractVersion(version) == "*" {
					continue
				}
				mod.Modules[name] = &models.Module{
					Name:     name,
					Version:  extractVersion(version),
					CheckSum: &models.CheckSum{Content: []byte(fmt.Sprintf("%s-%s", name, version))},
				}
			}
		}
		r := strings.TrimSuffix(strings.TrimPrefix(d.Resolved, "\""), "\"")
		if strings.Index(r, "#") > 0 {
			r = r[:strings.Index(r, "#")]
			mod.PackageDownloadLocation = r
		}
		if mod.PackageDownloadLocation == "" {
			r := "https://www.yarnpkg.com/package/%s"
			mod.PackageDownloadLocation = fmt.Sprintf(r, mod.Name)
		}
		mod.Supplier.Name = mod.Name

		mod.PackageURL = getPackageHomepage(filepath.Join(path, m.metadata.ModulePath[0], d.PkPath, m.metadata.Manifest[0]))
		h := fmt.Sprintf("%x", sha256.Sum256([]byte(mod.Name)))
		mod.CheckSum = &models.CheckSum{
			Algorithm: "SHA256",
			Value:     h,
		}
		licensePath := filepath.Join(path, m.metadata.ModulePath[0], d.PkPath, "LICENSE")
		if helper.Exists(licensePath) {
			r := reader.New(licensePath)
			s := r.StringFromFile()
			mod.Copyright = helper.GetCopyright(s)
		}

		modLic, err := helper.GetLicenses(filepath.Join(path, m.metadata.ModulePath[0], d.PkPath))
		if err != nil {
			modules = append(modules, mod)
			continue
		}
		mod.LicenseDeclared = helper.BuildLicenseDeclared(modLic.ID)
		mod.LicenseConcluded = helper.BuildLicenseConcluded(modLic.ID)
		mod.CommentsLicense = modLic.Comments
		if !helper.LicenseSPDXExists(modLic.ID) {
			mod.OtherLicense = append(mod.OtherLicense, modLic)
		}
		modules = append(modules, mod)
	}
	return modules, nil
}

func buildDepenenciesV2(path string, deps []dependencyV2, yarn *yarn) ([]models.Module, error) {
	modules := make([]models.Module, 0)
	rootModule, err := yarn.GetRootModule(path)
	if err != nil {
		log.Errorf("error creating root module - %s\n", err.Error())
		//return modules, err
	}

	sha256Hash := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%s", rootModule.Name, rootModule.Version))))
	rootModule.CheckSum = &models.CheckSum{
		Algorithm: "SHA256",
		Value:     sha256Hash,
	}

	rootModule.Supplier.Name = rootModule.Name

	if rootModule.PackageDownloadLocation == "" {
		rootModule.PackageDownloadLocation = rootModule.Name
	}

	// add the project module
	modules = append(modules, *rootModule)

	// for every dependency, add it to the root module
	// then parse its dependencies into sub-modules
	for _, dep := range deps {
		mod := models.Module{
			Name:     dep.Name,
			Version:  extractVersion(dep.Version),
			CheckSum: &models.CheckSum{Content: []byte(fmt.Sprintf("%s-%s", dep.Name, dep.Version))},
			//PackageDownloadLocation: dep.Resolution,
			Supplier: models.SupplierContact{
				Name: dep.Name,
			},
			PackageURL: getPackageHomepage(filepath.Join(path, yarn.metadata.ModulePath[0], dep.Name, yarn.metadata.Manifest[0])),
		}

		if dep.Resolution == "" {
			mod.PackageDownloadLocation = fmt.Sprintf("https://www.yarnpkg.com/package/%s", mod.Name)
		} else {
			mod.PackageDownloadLocation = dep.Resolution
		}

		log.Debugf("%#v\n", mod)
		licensePath := filepath.Join(path, yarn.metadata.ModulePath[0], dep.Name, "LICENSE")
		if helper.Exists(licensePath) {
			r := reader.New(licensePath)
			s := r.StringFromFile()
			mod.Copyright = helper.GetCopyright(s)
		}

		modLic, err := helper.GetLicenses(filepath.Join(path, yarn.metadata.ModulePath[0], dep.Name))
		if err != nil {
			log.Warnf("unable to get licenses for package %s - %s\n", dep.Name, err.Error())
		} else {
			mod.LicenseDeclared = helper.BuildLicenseDeclared(modLic.ID)
			mod.LicenseConcluded = helper.BuildLicenseConcluded(modLic.ID)
			mod.CommentsLicense = modLic.Comments
			if !helper.LicenseSPDXExists(modLic.ID) {
				mod.OtherLicense = append(mod.OtherLicense, modLic)
			}
		}

		// now add dependencies of dependencies
		if len(dep.Dependencies) > 0 {
			mod.Modules = map[string]*models.Module{}
			for subDepName, subDepVersion := range dep.Dependencies {
				mod.Modules[subDepName] = &models.Module{
					Name:     subDepName,
					Version:  extractVersion(subDepVersion),
					CheckSum: &models.CheckSum{Content: []byte(fmt.Sprintf("%s-%s", subDepName, subDepVersion))},
				}
			}
		}

		modules = append(modules, mod)

	}
	return modules, nil
}

func readLockFile(path string) ([]dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return []dependency{}, err
	}
	defer file.Close()
	p := make([]dependency, 0)
	i := -1
	scanner := bufio.NewScanner(file)

	isPk := false
	isDep := false
	for scanner.Scan() {
		text := scanner.Text()
		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}
		if strings.TrimSpace(text) == "" {
			isPk = false
			isDep = false
			continue
		}
		if isDep {
			p[i].Dependencies = append(p[i].Dependencies, text)
			continue
		}
		if isPk {
			if strings.HasPrefix(text, "  version ") {
				p[i].Version = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(text, "  version "), "\""), "\"")
				n := p[i].Name[:strings.Index(p[i].Name, "@")]
				p[i].Name = n
				p[i].PkPath = p[i].PkPath[:strings.LastIndex(p[i].PkPath, "@")]
				continue
			}
			if strings.HasPrefix(text, "  resolved ") {
				p[i].Resolved = strings.TrimPrefix(text, "  resolved ")
				continue
			}
			if strings.HasPrefix(text, "  integrity ") {
				p[i].Integrity = strings.TrimPrefix(text, "  integrity ")
				continue
			}
			if strings.HasPrefix(text, "  dependencies:") {
				isDep = true
				continue
			}
		}

		if !strings.HasPrefix(scanner.Text(), "  ") {
			isPk = true
			i++
			var dep dependency
			name := text
			name = strings.TrimSpace(name)
			if strings.Contains(name, ",") {
				s := strings.Split(name, ",")
				name = s[0]
			}
			name = strings.TrimPrefix(name, "\"")
			name = strings.TrimSuffix(name, ":")

			dep.PkPath = strings.TrimSuffix(name, "\"")
			name = strings.TrimPrefix(name, "@")

			dep.Name = name
			p = append(p, dep)
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return []dependency{}, err
	}

	return p, nil
}

func readLockV2File(path string) (yarnV2, error) {
	log.Debugf("reading lock file from %s", path)
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Infof("error parsing lock file (%s) as yarn v2 lock file - may be yarn v1.\n", path)
		log.Infof("error: %s\n", err.Error())
		return nil, err
	}

	log.Debugf("lock file conents: %s\n", string(fileBytes))

	yv2 := yarnV2{}

	err = yaml.Unmarshal(fileBytes, yv2)
	if err != nil {
		log.Infof("error unmarshalling lock file (%s) as yarn v2 lock file - may be yarn v1.\n", path)
		log.Infof("error: %s\n", err.Error())
		return nil, err
	}

	log.Debugf("yarn v2 lock: %#v\n", yv2)

	return yv2, nil
}

func getCopyright(path string) string {
	licensePath := filepath.Join(path, "LICENSE")
	if helper.Exists(licensePath) {
		r := reader.New(licensePath)
		s := r.StringFromFile()
		return helper.GetCopyright(s)
	}

	licenseMDPath, err := filepath.Glob(filepath.Join(path, "LICENSE*"))
	if err != nil {
		return ""
	}
	if len(licenseMDPath) > 0 && helper.Exists(licenseMDPath[0]) {
		r := reader.New(licenseMDPath[0])
		s := r.StringFromFile()
		return helper.GetCopyright(s)
	}

	return ""
}

func getPackageHomepage(path string) string {
	r := reader.New(path)
	pkResult, err := r.ReadJson()
	if err != nil {
		return ""
	}
	if pkResult["homepage"] != nil {
		return helper.RemoveURLProtocol(pkResult["homepage"].(string))
	}
	return ""
}

func extractVersion(s string) string {
	t := strings.TrimPrefix(s, "^")
	t = strings.TrimPrefix(t, "~")
	t = strings.TrimPrefix(t, ">")
	t = strings.TrimPrefix(t, "=")

	t = strings.Split(t, " ")[0]
	return t
}

func appendNestedDependencies(deps []dependency) []dependency {
	allDeps := make([]dependency, 0)
	for _, d := range deps {
		allDeps = append(allDeps, d)
		if len(d.Dependencies) > 0 {
			for _, depD := range d.Dependencies {
				ar := strings.Split(strings.TrimSpace(depD), " ")

				name := strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(ar[0], "\""), "\""), "@")

				if len(ar) < 2 {
					// remove single check for optionalDependencies and ignore all deps that do not
					// have specified versions
					fmt.Printf("warning: no version specified when parsing dependency string %s (%#v) for parent dependency %s\n", depD, name, d.Name)
					continue
				}

				version := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(ar[1]), "\""), "\"")
				if extractVersion(version) == "*" {
					continue
				}
				allDeps = append(allDeps, dependency{Name: name, Version: extractVersion(version)})
			}
		}
	}
	return allDeps
}

func appendNestedDependenciesV2(y yarnV2) ([]dependencyV2, error) {
	allDeps := make([]dependencyV2, 0)
	for _, dep := range y {
		name := strings.Split(dep.Resolution, "@npm:")[0]
		dep.Name = name
		allDeps = append(allDeps, dep)

		for subDepName, subDepVersion := range dep.Dependencies {
			allDeps = append(allDeps, dependencyV2{
				Name:         subDepName,
				Version:      subDepVersion,
				Dependencies: map[string]string{},
			})
		}
	}

	return allDeps, nil
}
