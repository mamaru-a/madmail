/*
Maddy Mail Server - Composable all-in-one email server.
Copyright © 2019-2020 Max Mazurov <fox.cpp@disroot.org>, Maddy Mail Server contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Package connmetrics provides a net.Listener wrapper that reports the number
// of currently open client connections as a Prometheus gauge.
package connmetrics

import (
	"net"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var activeConns = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: "maddy",
		Name:      "conns_active",
		Help:      "Amount of client connections currently open",
	},
	[]string{"module"},
)

func init() {
	prometheus.MustRegister(activeConns)
}

// NewListener wraps inner so that every accepted connection increments the
// maddy_conns_active gauge for module and decrements it when closed.
//
// It must be applied to the raw listener, before tls.NewListener: the
// connections it returns are not *tls.Conn, and go-imap type-asserts for that
// to pick up the TLS state of an implicit-TLS connection.
func NewListener(inner net.Listener, module string) net.Listener {
	return &listener{Listener: inner, gauge: activeConns.WithLabelValues(module)}
}

// WrapConn accounts for a single connection that was not obtained from a
// listener wrapped by NewListener. The same "wrap it before TLS" rule applies.
func WrapConn(c net.Conn, module string) net.Conn {
	g := activeConns.WithLabelValues(module)
	g.Inc()
	return &conn{Conn: c, gauge: g}
}

type listener struct {
	net.Listener
	gauge prometheus.Gauge
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.gauge.Inc()
	return &conn{Conn: c, gauge: l.gauge}, nil
}

type conn struct {
	net.Conn
	gauge prometheus.Gauge
	once  sync.Once
}

// Close decrements the gauge exactly once, no matter how many times it is
// called - both go-imap and go-smtp close a connection more than once on some
// paths.
func (c *conn) Close() error {
	c.once.Do(c.gauge.Dec)
	return c.Conn.Close()
}
