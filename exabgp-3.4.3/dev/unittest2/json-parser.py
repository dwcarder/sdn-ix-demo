#!/usr/bin/env python
# encoding: utf-8
"""
protocol.py

Created by Thomas Mangin on 2013-03-23.
Copyright (c) 2009-2013 Exa Networks. All rights reserved.
"""

import unittest
import tempfile
import os
import cProfile

configuration = """
{
	"_": "every key starting with an _ is ignored, but kept",
  "_0": "it can be useful to add comment in the configuration file",
	"_1": "keep in mind that the configuration has no ordering",
	"exabgp": 3,
	"neighbor": {
		"n-0": {
			"_": "will pass received routes to the program",
			"tcp": {
				"local": "127.0.0.1",
				"peer": "127.0.0.1",
				"ttl-security": false,
				"md5": "secret"
			},
			"api": {
				"syslog-text": [ "receive-routes" ],
				"syslog-json": [ "neighbor-changes","send-packets","receive-packets","receive-routes" ]
			},
			"session": {
				"router-id": "127.0.0.1",
				"hold-time": 180,
				"asn": {
					"local": 65500,
					"peer": 65500
				},
				"capability": {
					"family": {
						"ipv4": ["unicast","multicast","nlri-mpls","mpls-vpn","flow-vpn","flow"],
						"ipv6": ["unicast"],
						"_ip": ["unicast","flow"],
						"_alias": "all",
						"_alias": "minimal"
					},
					"asn4": true,
					"route-refresh": true,
					"graceful-restart": false,
					"multi-session": false,
					"add-path": false
				}
			},
			"announce": [
				"local-routes",
				"off-goes-the-ddos"
			]
		}
	},
	"api": {
		"_": "the names defined here can be used in the neighbors",
		"syslog-json": {
			"encoder": "json",
			"program": "etc/exabgp/processes/syslog-1.py"
		},
		"_": "be careful to not loose comment if you use multiple _",
		"syslog-text": {
			"encoder": "text",
			"program": "etc/exabgp/processes/syslog-2.py"
		}
	},
	"attribute": {
		"normal-ebgp-attributes": {
			"origin": "igp",
			"as-path": [ 3356, 1239, 38040, 9737 ],
			"local-preference": 500,
			"aggregator": "10.0.0.1",
			"atomic-aggregate": false,
			"originator-id": "10.0.0.1",
			"med": 10,
			"community": [[3356,2], [3356,22], [3356,86], [3356,500], [3356,666], [3356,2064], "no-export"],
			"cluster-list": [],
			"extended-community": []
		},
		"simple-attributes": {
			"next-hop": "212.73.207.153",
			"origin": "igp",
			"as-path": [ 3356, 1239, 38040, 9737 ],
			"local-preference": 500,
			"aggregator": "10.0.0.1",
			"atomic-aggregate": false,
			"originator-id": "10.0.0.1",
			"med": 10,
			"community": [[3356,2], [3356,22], [3356,86], [3356,500], [3356,666], [3356,2064]],
			"cluster-list": [],
			"extended-community": []
		}
	},
	"flow": {
		"filtering-condition": {
			"simple-ddos": {
				"source": "10.0.0.1/32",
				"destination": "192.168.0.1/32",
				"port": [[["=",80]]],
				"protocol": "tcp"
			},
			"port-block": {
				"port": [ [["=",80 ]],[["=",8080]] ],
				"destination-port": [ [[">",8080],["<",8088]], [["=",3128]] ],
				"source-port": [[[">",1024]]],
				"protocol": [ "tcp", "udp" ]
			},
			"complex-attack": {
				"packet-length": [ [[">",200],["<",300]], [[">",400],["<",500]] ],
				"_fragment": ["not-a-fragment"],
				"fragment": ["first-fragment","last-fragment" ],
				"_icmp-type": [ "unreachable", "echo-request", "echo-reply" ],
				"icmp-code": [ "host-unreachable", "network-unreachable" ],
				"tcp-flags": [ "urgent", "rst" ],
				"dscp": [ 10, 20 ]
			}
		},
		"filtering-action": {
			"make-it-slow": {
					"rate-limit": 9600
			},
			"drop-it": {
					"discard": true
			},
			"send-it-elsewhere": {
					"redirect": "65500:12345"
			},
			"send-it-community": {
				"redirect": "1.2.3.4:5678",
				"community": [[30740,0], [30740,30740]]
			}
		}
	},
	"update": {
		"prefix": {
			"local-routes": {
				"normal-ebgp-attributes": {
					"192.168.0.0/24": {
						"next-hop": "192.0.2.1"
					},
					"192.168.0.0/24": {
						"next-hop": "192.0.2.2"
					}
				},
				"simple-attributes": {
					"_": "it is possible to overwrite some previously defined attributes",
					"192.168.1.0/24": {
						"next-hop": "192.0.2.1"
					},
					"192.168.2.0/24": {
					}
				}
			},
			"remote-routes": {
				"simple-attributes": {
					"10.0.0.0/16": {
						"_": "those three can be defined everywhere too, but require the right capability",
						"label": [0, 1],
						"path-information": 0,
						"route-distinguisher": "1:0.0.0.0",
						"split": 24
					}
				}
			}
		},
		"flow": {
			"off-goes-the-ddos": {
				"simple-ddos": "make-it-slow",
				"port-block": "drop-it"
			},
			"saved_just_in_case": {
				"complex-attack": "send-it-elsewhere"
			}
		}
	}
}
"""

def _make_config ():
	name = tempfile.mkstemp(suffix='.exa')[1]
	print 'creating configuration file %s' % name
	with open(name,'w') as f:
		f.write(configuration)
	print 'created'
	return name


def test ():
	from exabgp.configuration.json import load
from exabgp.configuration.json import JSONError

	try:
		name = _make_config()
	except:
		return 'could not create temp file'

	try:
		json = load(name)
	except JSONError,e:
		os.remove(name)
		return 'configuration parsing file: %s' % str(e)

	del json

class TestData (unittest.TestCase):

	def test_1 (self):
		if not os.environ.get('profile',False):
			result = test()
			if result: self.fail(result)

	def test_2 (self):
		if not not os.environ.get('profile',False):
			cProfile.run('test()')

if __name__ == '__main__':
	unittest.main()


	# import cProfile
	# print 'profiling'
	# cProfile.run('unittest.main()','profile.info')
