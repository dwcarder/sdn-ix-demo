# encoding: utf-8
"""
registry.py

Created by Thomas Mangin on 2014-06-22.
Copyright (c) 2014-2014 Exa Networks. All rights reserved.
"""

# the replace Fxception, and give line etc.
class Raised (Exception):
	pass

class Entry (object):
	def _drop_colon (self,tokeniser):
		if tokeniser() != ';':
			raise Raised('missing semi-colon')

	def _drop_parenthesis (self,tokeniser):
		if tokeniser() != '{':
			raise Raised('missing semi-colon')


class Registry (object):
	def __init__ (self):
		self.stack = []
		self._klass = {}
		self._handler = {}

	# self.location set by Registry

	def register (self,cls,location):
		cls.register(self,location)

	def register_class (self,cls):
		print "class %s registered" % cls.__name__
		if not cls in self._klass:
			self._klass[cls] = cls()

	def register_hook (self,cls,action,position,function):
		key = '/'.join(position)
		if action in self._handler:
			raise Raised('conflicting handlers')
		self._handler.setdefault(key,{})[action] = getattr(cls,function)
		print "%-35s %-7s %s.%-20s registered" % (key if key else 'root',action,cls.__name__,function)

	def handle (self,tokeniser):
		def run (search,section,location):
			key = '/'.join(search)
			function = self._handler.get(key,{}).get(section,None)

			if function:
				print 'hit %s/%s' % (key,section)
				instance = self._klass.setdefault(function.im_class,function.im_class())
				instance.location = location
				function(instance,tokeniser)
				return True
			return False

		while True:
			token = tokeniser()
			if not token: break

			if run(self.stack + [token,],'enter',self.stack):
				self.stack.append(token)
				continue

			if run(self.stack+[token,],'action',self.stack+[token]):
				continue

			if token != '}':
				# we need the line and position at this level
				raise Exception('no enter or action code registered for path /%s ( token was %s )' % ('/'.join(self.stack),token))

			if run(self.stack,'exit',self.stack[:-1]):
				self.stack.pop()
				continue

			# we need the line and position at this level
			raise Exception('no exit code registered for %s' % '/'.join(self.stack))
