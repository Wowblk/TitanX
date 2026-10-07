package plugins

import "github.com/hashicorp/go-version"

const SIGNATURE = "B4BDF874-8C03-5BD8-8FD7-5E409DFD82C0"

type Info struct {
	Name        string
	Description string
	Signature   string
	Version     *version.Version
}
