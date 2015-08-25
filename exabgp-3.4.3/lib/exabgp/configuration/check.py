# encoding: utf-8
"""
check.py

Created by Thomas Mangin on 2009-08-25.
Copyright (c) 2009-2014 Exa Networks. All rights reserved.
"""

# common

from exabgp.protocol.family import known_families
from exabgp.bgp.message.update import Update
from exabgp.bgp.message.open import Open
from exabgp.bgp.message.open.capability import Capabilities
from exabgp.bgp.message.open.capability import Capability
from exabgp.bgp.message.open.capability.negotiated import Negotiated
from exabgp.bgp.message.notification import Notify

# check_neighbor

from exabgp.util.od import od
from exabgp.rib.change import Change

# check_update

from exabgp.reactor.peer import Peer
from exabgp.reactor.api.encoding import JSON

# check_notification

from exabgp.bgp.message.notification import Notification

# =============================================================== check_neighbor
# ...

def check_neighbor (neighbor):
	from exabgp.logger import Logger

	logger = Logger()
	logger._parser = True
	logger.parser('\ndecoding routes in configuration')

	n = neighbor[neighbor.keys()[0]]

	path = {}
	for f in known_families():
		if n.add_path:
			path[f] = n.add_path

	capa = Capabilities().new(n,False)
	capa[Capability.ID.ADD_PATH] = path
	capa[Capability.ID.MULTIPROTOCOL] = n.families()

	o1 = Open(4,n.local_as,str(n.local_address),capa,180)
	o2 = Open(4,n.peer_as,str(n.peer_address),capa,180)
	negotiated = Negotiated(n)
	negotiated.sent(o1)
	negotiated.received(o2)
	#grouped = False

	for nei in neighbor.keys():
		for message in neighbor[nei].rib.outgoing.updates(False):
			pass

		for change1 in neighbor[nei].rib.outgoing.sent_changes():
			str1 = change1.extensive()
			packed = list(Update([change1.nlri],change1.attributes).messages(negotiated))
			pack1 = packed[0]

			logger.parser('parsed route requires %d updates' % len(packed))
			logger.parser('update size is %d' % len(pack1))

			logger.parser('parsed route %s' % str1)
			logger.parser('parsed hex   %s' % od(pack1))

			# This does not take the BGP header - let's assume we will not break that :)
			try:
				logger.parser('')  # new line

				pack1s = pack1[19:] if pack1.startswith('\xFF'*16) else pack1
				update = Update.unpack_message(pack1s,negotiated)

				change2 = Change(update.nlris[0],update.attributes)
				str2 = change2.extensive()
				pack2 = list(Update([update.nlris[0]],update.attributes).messages(negotiated))[0]

				logger.parser('recoded route %s' % str2)
				logger.parser('recoded hex   %s' % od(pack2))

				str1r = str1.replace(' med 100','').replace(' local-preference 100','').replace(' origin igp','')
				str2r = str2.replace(' med 100','').replace(' local-preference 100','').replace(' origin igp','')

				skip = False

				if str1r != str2r:
					if 'attribute [' in str1r and ' 0x00 ' in str1r:
						# we do not decode non-transitive attributes
						logger.parser('skipping string check on update with non-transitive attribute(s)')
						skip = True
					else:
						logger.parser('strings are different:')
						logger.parser('[%s]'%str1r)
						logger.parser('[%s]'%str2r)
						return False
				else:
						logger.parser('strings are fine')

				if skip:
					logger.parser('skipping encoding for update with non-transitive attribute(s)')
				elif pack1 != pack2:
					logger.parser('encoding are different')
					logger.parser('[%s]'%od(pack1))
					logger.parser('[%s]'%od(pack2))
					return False
				else:
					logger.parser('encoding is fine')
					logger.parser('----------------------------------------')

			except Notify,e:
				logger.parser('----------------------------------------')
				logger.parser(str(e))
				logger.parser('----------------------------------------')
				return False

	return True



# ================================================================ check_message
#

def check_message (neighbor,message):
	message = message.replace(':','')
	raw = ''.join(chr(int(_,16)) for _ in (message[i*2:(i*2)+2] for i in range(len(message)/2)))

	if raw.startswith('\xff'*16):
		kind = ord(raw[18])
		size = (ord(raw[16]) << 16) + (ord(raw[17]))
		# XXX: FIXME: check size

		if kind == 1:
			return check_open(neighbor,raw[18:])
		elif kind == 2:
			return check_update(neighbor,raw)
		elif kind == 3:
			return check_notification(raw)
	else:
		return check_update(neighbor,raw)


# ================================================================= check_update
#

def check_open (neighbor,raw):
	pass


# ================================================================= check_update
#

def check_update (neighbor,raw):
	from exabgp.logger import Logger

	logger = Logger()
	logger._parser = True
	logger.parser('\ndecoding routes in configuration')

	n = neighbor[neighbor.keys()[0]]
	p = Peer(n,None)

	path = {}
	for f in known_families():
		if n.add_path:
			path[f] = n.add_path

	capa = Capabilities().new(n,False)
	capa[Capability.ID.ADD_PATH] = path
	capa[Capability.ID.MULTIPROTOCOL] = n.families()

	o1 = Open(4,n.local_as,str(n.local_address),capa,180)
	o2 = Open(4,n.peer_as,str(n.peer_address),capa,180)
	negotiated = Negotiated(n)
	negotiated.sent(o1)
	negotiated.received(o2)
	#grouped = False

	while raw:
		if raw.startswith('\xff'*16):
			kind = ord(raw[18])
			size = (ord(raw[16]) << 16) + (ord(raw[17]))

			injected,raw = raw[19:size],raw[size:]

			if kind == 2:
				logger.parser('the message is an update')
				decoding = 'update'
			else:
				logger.parser('the message is not an update (%d) - aborting' % kind)
				return False
		else:
			logger.parser('header missing, assuming this message is ONE update')
			decoding = 'update'
			injected,raw = raw,''

		try:
			# This does not take the BGP header - let's assume we will not break that :)
			update = Update.unpack_message(injected,negotiated)
		except KeyboardInterrupt:
			raise
		except Notify,e:
			logger.parser('could not parse the message')
			logger.parser(str(e))
			return False
		except Exception,e:
			logger.parser('could not parse the message')
			logger.parser(str(e))
			return False

		logger.parser('')  # new line
		for number in range(len(update.nlris)):
			change = Change(update.nlris[number],update.attributes)
			logger.parser('decoded %s %s %s' % (decoding,change.nlri.action,change.extensive()))
		logger.parser('update json %s' % JSON('3.4.0').update(p,update,'',''))

	return True


# ================================================================= check_update
#

def check_notification (raw):
	notification = Notification.unpack_message(raw[18:],None)
	# XXX: FIXME: should be using logger here
	print notification
	return True
