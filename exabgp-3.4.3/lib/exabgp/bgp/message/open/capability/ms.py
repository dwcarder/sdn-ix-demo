# encoding: utf-8
"""
ms.py

Created by Thomas Mangin on 2012-07-17.
Copyright (c) 2009-2013 Exa Networks. All rights reserved.
"""

from exabgp.bgp.message.open.capability import Capability

# ================================================================= MultiSession
#

class MultiSession (Capability,list):
	def __init__ (self):
		self.ID = Capability.ID.MULTISESSION
		list.__init__(self)

	def set (self,data):
		self.extend(data)
		return self

	# XXX: FIXME: Looks like we could do with something in this Caoability
	def __str__ (self):
		info = ' (RFC)' if self.ID == Capability.ID.MULTISESSION else ''
		return 'Multisession%s %s' % (info,' '.join([str(capa) for capa in self]))

	def json (self):
		variant = 'RFC' if self.ID == Capability.ID.MULTISESSION else 'Cisco'
		return '{ "name": "multisession", "variant": "%s" ,"capabilities": [%s ] }' % (variant, ','.join(' %s' % str(capa) for capa in self))

	def extract (self):
		rs = [chr(0),]
		for v in self:
			rs.append(chr(v))
		return rs

	@staticmethod
	def unpack (capability,instance,data):
		# XXX: FIXME: we should set that that instance was seen and raise if seen twice
		return instance

MultiSession.register_capability(Capability.ID.MULTISESSION_CISCO)
MultiSession.register_capability(Capability.ID.MULTISESSION)
