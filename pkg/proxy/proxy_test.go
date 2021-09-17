// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package proxy

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type ProxySuite struct{}

var _ = Suite(&ProxySuite{})

type MockDatapathUpdater struct{}

func (m *MockDatapathUpdater) InstallProxyRules(proxyPort uint16, ingress bool, name string) error {
	return nil
}

func (m *MockDatapathUpdater) SupportsOriginalSourceAddr() bool {
	return true
}

func (s *ProxySuite) TestPortAllocator(c *C) {
	mockDatapathUpdater := &MockDatapathUpdater{}

	stateDir := c.MkDir()
	p := StartProxySupport(10000, 20000, stateDir, nil, nil, mockDatapathUpdater, nil)

	port, err := p.AllocateProxyPort("listener1", true)
	c.Assert(err, IsNil)
	c.Assert(port, Not(Equals), 0)

	port1, err := GetProxyPort("listener1")
	c.Assert(err, IsNil)
	c.Assert(port1, Equals, port)

	// Another allocation for the same name gets the same port
	port1a, err := p.AllocateProxyPort("listener1", true)
	c.Assert(err, IsNil)
	c.Assert(port1a, Equals, port1)

	name, pp := findProxyPortByType(ProxyTypeCRD, true)
	c.Assert(name, Equals, "listener1")
	c.Assert(pp.proxyType, Equals, ProxyTypeCRD)
	c.Assert(pp.proxyPort, Equals, port)
	c.Assert(pp.ingress, Equals, true)
	c.Assert(pp.configured, Equals, true)
	c.Assert(pp.isStatic, Equals, false)
	c.Assert(pp.nRedirects, Equals, 0)
	c.Assert(pp.rulesPort, Equals, uint16(0))

	err = p.ReleaseProxyPort("listener1")
	c.Assert(err, IsNil)

	// ProxyPort lingers and can still be found, but it's port is zeroed
	port1b, err := GetProxyPort("listener1")
	c.Assert(err, IsNil)
	c.Assert(port1b, Equals, uint16(0))
	c.Assert(pp.proxyPort, Equals, uint16(0))
	c.Assert(pp.configured, Equals, false)
	c.Assert(pp.nRedirects, Equals, 0)

	// the port was never acked, so rulesPort is 0
	c.Assert(pp.rulesPort, Equals, uint16(0))

	// Allocates a different port (due to port was never acked)
	port2, err := p.AllocateProxyPort("listener1", true)
	c.Assert(err, IsNil)
	c.Assert(port2, Not(Equals), port)
	c.Assert(pp.proxyType, Equals, ProxyTypeCRD)
	c.Assert(pp.ingress, Equals, true)
	c.Assert(pp.proxyPort, Equals, port2)
	c.Assert(pp.configured, Equals, true)
	c.Assert(pp.isStatic, Equals, false)
	c.Assert(pp.nRedirects, Equals, 0)
	c.Assert(pp.rulesPort, Equals, uint16(0))

	// Ack configures the port to the datapath
	err = p.AckProxyPort("listener1")
	c.Assert(err, IsNil)
	c.Assert(pp.nRedirects, Equals, 1)
	c.Assert(pp.rulesPort, Equals, port2)

	// Another Ack takes another reference
	err = p.AckProxyPort("listener1")
	c.Assert(err, IsNil)
	c.Assert(pp.nRedirects, Equals, 2)
	c.Assert(pp.rulesPort, Equals, port2)

	// 1st release decreases the count
	err = p.ReleaseProxyPort("listener1")
	c.Assert(err, IsNil)
	c.Assert(pp.nRedirects, Equals, 1)
	c.Assert(pp.configured, Equals, true)
	c.Assert(pp.proxyPort, Equals, port2)

	// 2nd release decreases the count to zero
	err = p.ReleaseProxyPort("listener1")
	c.Assert(err, IsNil)
	c.Assert(pp.nRedirects, Equals, 0)
	c.Assert(pp.configured, Equals, false)
	c.Assert(pp.proxyPort, Equals, uint16(0))
	c.Assert(pp.rulesPort, Equals, port2)

	// extra releases are idempotent
	err = p.ReleaseProxyPort("listener1")
	c.Assert(err, IsNil)
	c.Assert(pp.nRedirects, Equals, 0)
	c.Assert(pp.configured, Equals, false)
	c.Assert(pp.proxyPort, Equals, uint16(0))
	c.Assert(pp.rulesPort, Equals, port2)

	// mimic some other process taking the port
	allocatedPorts[port2] = true

	// Allocate again, this time a different port is allocated
	port3, err := p.AllocateProxyPort("listener1", true)
	c.Assert(err, IsNil)
	c.Assert(port3, Not(Equals), uint16(0))
	c.Assert(port3, Not(Equals), port2)
	c.Assert(port3, Not(Equals), port1)
	c.Assert(pp.proxyType, Equals, ProxyTypeCRD)
	c.Assert(pp.ingress, Equals, true)
	c.Assert(pp.proxyPort, Equals, port3)
	c.Assert(pp.configured, Equals, true)
	c.Assert(pp.isStatic, Equals, false)
	c.Assert(pp.nRedirects, Equals, 0)
	c.Assert(pp.rulesPort, Equals, port2)

	// Ack configures the port to the datapath
	err = p.AckProxyPort("listener1")
	c.Assert(err, IsNil)
	c.Assert(pp.nRedirects, Equals, 1)
	c.Assert(pp.rulesPort, Equals, port3)

	// Release marks the port as unallocated
	err = p.ReleaseProxyPort("listener1")
	c.Assert(err, IsNil)
	c.Assert(pp.nRedirects, Equals, 0)
	c.Assert(pp.configured, Equals, false)
	c.Assert(pp.proxyPort, Equals, uint16(0))
	c.Assert(pp.rulesPort, Equals, port3)

	inuse, exists := allocatedPorts[port3]
	c.Assert(exists, Equals, true)
	c.Assert(inuse, Equals, false)

	// No-one used the port so next allocation gets the same port again
	port4, err := p.AllocateProxyPort("listener1", true)
	c.Assert(err, IsNil)
	c.Assert(port4, Equals, port3)
	c.Assert(pp.proxyType, Equals, ProxyTypeCRD)
	c.Assert(pp.ingress, Equals, true)
	c.Assert(pp.proxyPort, Equals, port4)
	c.Assert(pp.configured, Equals, true)
	c.Assert(pp.isStatic, Equals, false)
	c.Assert(pp.nRedirects, Equals, 0)
	c.Assert(pp.rulesPort, Equals, port3)
}
