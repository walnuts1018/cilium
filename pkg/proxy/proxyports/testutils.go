// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxyports

type MockDatapathUpdater struct{}

var _ DatapathUpdater = &MockDatapathUpdater{}

func (m *MockDatapathUpdater) InstallProxyRules(proxyPort uint16, name string) {}

func (m *MockDatapathUpdater) GetProxyPorts() map[string]uint16 {
	return nil
}
