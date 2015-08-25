# encoding: utf-8
"""
bgp.py

Created by Thomas Mangin on 2012-07-08.
Copyright (c) 2009-2013 Exa Networks. All rights reserved.
"""

# ===================================================================== PathInfo
# RFC draft-ietf-idr-add-paths-09

class PathInfo (object):

	__slots__ = ['path_info']

	def __init__ (self,integer=None,ip=None,packed=None):
		if packed:
			self.path_info = packed
		elif ip:
			self.path_info = ''.join([chr(int(_)) for _ in ip.split('.')])
		elif integer:
			self.path_info = ''.join([chr((integer>>offset) & 0xff) for offset in [24,16,8,0]])
		else:
			self.path_info = ''
		#sum(int(a)<<offset for (a,offset) in zip(ip.split('.'), range(24, -8, -8)))

	def __len__ (self):
		return len(self.path_info)

	def json (self):
		if self.path_info:
			return '"path-information": "%s"' % '.'.join([str(ord(_)) for _ in self.path_info])
		return ''

	def __str__ (self):
		if self.path_info:
			return ' path-information %s' % '.'.join([str(ord(_)) for _ in self.path_info])
		return ''

	def pack (self):
		if self.path_info:
			return self.path_info
		return '\x00\x00\x00\x00'

PathInfo.NOPATH = PathInfo()
