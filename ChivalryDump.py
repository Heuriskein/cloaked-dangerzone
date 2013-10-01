# \gamedir\chivalrymedievalwarfare
import sys
import socket
import struct
import threading
import Queue
import random
import bz2
import json
import ChivDumpOutputMethods 
from optparse import OptionParser
from base64 import b16encode,b64encode

l_stream = threading.Lock()
l_data = threading.Lock()


# ec2 instance from command line
parser = OptionParser()

parser.add_option("--id", dest="AWSAccessKeyId",
                  help="The AWSAcessKeyId")

parser.add_option("--keyfilepath", dest="AWSSecretKeyFile",
                  help="The AWSSecretKey")

parser.add_option("--rabbit", dest="rabbitHost",
                  help="The rabbitHost")

parser.add_option("--gamename", dest="gamename", default='chiv',
                  help="For naming S3 folders, defaults to chiv.")

parser.add_option("--gamehostip", dest="gamehostip", default=None,
                  help="Host option for testing this on a specific Server.")

parser.add_option("--gamehostport", dest="gamehostport", default=None,
                  help="Port option for testing this on a specific Server.")

parser.add_option("--s3bucket", dest="s3bucket", default=None,
                  help="TheS3Bucket you want to write data too.")

(options, args) = parser.parse_args()


g_S3BucketName = options.s3bucket
g_AWSAccessKeyId=options.AWSAccessKeyId

fp = open(options.AWSSecretKeyFile,'rb')
g_AWSSecretKey= fp.readline().strip('\n')
fp.close()

rabbitHost=options.rabbitHost 
g_Game=options.gamename
g_GameHostIp= options.gamehostip
g_GameHostPort = options.gamehostport

g_serverTimeouts = 0
g_unsupportedServerProtocols = 0
g_differentGames = 0
g_malformedPackets = 0 

NUM_THREADS = 5
END_OF_LIST_IP = ( '0.0.0.0', 0 )
VALVE_MASTER_RESPONSE_HEADER = '\xFF\xFF\xFF\xFF\x66\x0A'
STEAM_HEADER = '\xFF\xFF\xFF\xFF'

# /** Game rule for if the server has a password. */
RULE_PASSWORD = "p1342177286";
# /** Game rule for the server's minimum rank. */
RULE_MIN_RANK = "p1342177292";
# /** Game rule for the server's maximum rank. */
RULE_MAX_RANK = "p1342177293";
# /** Game rule for the server's perspective. */
RULE_PERSPECTIVE = "p1342177291";

masterList = [
  # ( 'hl1master.steampowered.com'  , 27010 ),
  ( 'hl1master.steampowered.com'  , 27011 ),
  # ( 'hl1master.steampowered.com'  , 27012 ),
  # ( 'hl2master.steampowered.com'   , 27010 ),
  ( 'hl2master.steampowered.com'   , 27011 ),
  # ( 'hl2master.steampowered.com'   , 27012 ),
  # ( '69.28.151.162'          , 27010 ), # SiN 1 Multiplayer - documentation indicates might be out of date.
  # ( '69.28.158.131'          , 27014 ),
  # ( '60.121.184.3'          , 13313 ), # From random launch.log - Probably not interesting
  ( '46.165.194.16'          , 27010 ), # This worked at one point
  # ( '46.165.194.16'          , 27011 ),
  # ( '46.165.194.16'          , 27012 ),
  # ( '208.64.200.201'        , 27018 ),
  
]

def ExtractString(s):
  index = s.find('\0')
  if index == -1:
    raise ValueError, "No terminator found"
  else:
    return s[:index], s[index+1:]

def PutString(s):
  return s + '\0'

def ExtractStruct(s, fmt):
  if not fmt.startswith('<'):
    # everything in the steam spec is little-endian
    fmt = '<' + fmt
  size = struct.calcsize(fmt)
  return struct.unpack(fmt, s[:size])[0], s[size:]
    
def ParseMasterResponse(response):
  data, address = response
  
  if (data[:6] != VALVE_MASTER_RESPONSE_HEADER):
    sys.exit('Got bad Valve Response header. Expected "{0}" got "{1}"'.format(VALVE_MASTER_RESPONSE_HEADER, data[:6]))
  
  data = data[6:]
  
  while True:
    try:
      a,b,c,d, port = struct.unpack('>BBBBH', data[:6])
    except struct.error:
      return
    val = ('{0}.{1}.{2}.{3}'.format(a,b,c,d), port)
    #print val
    yield val
    data = data[6:]
  
def ReceiveServerPackets(sock):
  bufs = None
  while True:
    data, address = sock.recvfrom(1400)
    t_locals.stream.append('R: {0}'.format(b16encode(data)))
    #print b16encode(data)
    header, data = ExtractStruct(data, 'l')
    if (header == -1):
      # Single packet
      if bufs is not None:
        raise MalformedPacket, 'Got single packet while waiting for multi packet'
      return data
      
    if (header == -2):
      # Multiple packets
      id, data = ExtractStruct(data, 'l')
      compressed = (id & 0x80000000) != 0
      total, data = ExtractStruct(data, 'B')
      number, data = ExtractStruct(data, 'B')
      size, data = ExtractStruct(data, 'h')
      if (number == 0 and compressed):
        decompressedSize, data = ExtractStruct(data, 'l')
        crc32, data = ExtractStruct(data, 'l')
      
      if bufs is None:
        bufs = [ None ] * total
      elif len(bufs) != total:
        raise MalformedPacket, 'Got unexpected number of bufs'
      
      # I guess we could receive a duplicate
      if bufs[number] is not None and bufs[number] != data:
        raise MalformedPacket, 'Got different version of buf {0}'.format(number)
        
      subheader, bufs[number] = ExtractStruct(data, 'l')
      if subheader != -1:
        raise MalformedPacket, 'Subheader had unexpected value {0}'.format(subheader)
        
      if None not in bufs:
        data = ''.join(bufs)
        if compressed:
          return bz2.decompress(data)
        else:
          return data
    
def ParseInfoResponse(data):
  header, data = ExtractStruct(data, 'c')
  if header == 'm':
    raise UnsupportedProtocol, 'Goldsource Server'
  if header != 'I':
    raise MalformedPacket, 'Got header {0} expected {1}'.format(header, 'I')
    
  result = {}
  result['protocol'], data = ExtractStruct(data, 'B')
  result['name'], data = ExtractString(data)
  result['map'], data = ExtractString(data)
  result['folder'], data = ExtractString(data)
  result['game'], data = ExtractString(data)
  result['steamappid'], data = ExtractStruct(data, 'h')
  result['players'], data = ExtractStruct(data, 'B')
  result['max_players'], data = ExtractStruct(data, 'B')
  result['bots'], data = ExtractStruct(data, 'B')
  result['server_type'], data = ExtractStruct(data, 'c') # D = Dedicated, L = Non-dedicated, P = SourceTV
  result['environment'], data = ExtractStruct(data, 'c') # L = Linux, W = Windows
  result['visibility'], data = ExtractStruct(data, 'B') # 0 = Public, 1 = Private
  result['vac'], data = ExtractStruct(data, 'B') # 0 = Unsecured, 1 = Secured
  result['version'], data = ExtractString(data)
  if (len(data) > 0):
    edf, data = ExtractStruct(data, 'B')
    if (edf & 0x80):
      result['port'], data = ExtractStruct(data, 'h')
    if (edf & 0x10):
      result['steamid'], data = ExtractStruct(data, 'q')
    if (edf & 0x40):
      result['sourcetv_port'], data = ExtractStruct(data, 'h')
      result['sourcetv_name'], data = ExtractString(data)
    if (edf & 0x20):
      result['keywords'], data = ExtractString(data)
    if (edf & 0x01):
      result['gameid'], data = ExtractStruct(data, 'q')
  
  if len(data) != 0:
    raise MalformedPacket, 'Did not consume full packet (info)'
  
  return result
  
def ParseChallengeResponse(data):
  header, data = ExtractStruct(data, 'c')
  if header != 'A':
    raise MalformedPacket, 'Got header {0} expected {1}'.format(header, 'A')
  challenge, data = ExtractStruct(data, 'l')
  
  if len(data) != 0:
    raise MalformedPacket, 'Did not consume full packet (challenge)'
  
  t_locals.stream.append('Got challenge {0}'.format(challenge))
  return challenge
  
def ParseRulesResponse(data):
  header, data = ExtractStruct(data, 'c')
  if header != 'E':
    raise MalformedPacket, 'Got header {0} expected {1}'.format(header, 'E')
  
  rules = {}
  numRules, data = ExtractStruct(data, 'h')
  for i in xrange(numRules):
    name, data = ExtractString(data)
    value, data = ExtractString(data)
    rules[name] = value
  
  if len(data) != 0:
    raise MalformedPacket, 'Did not consume full packet (rules)'
    
  return rules
  
def ParsePlayersResponse(data):
  header, data = ExtractStruct(data, 'c')
  if header != 'D':
    raise MalformedPacket, 'Got header {0} expected {1}'.format(header, 'D')
  
  numPlayers, data = ExtractStruct(data, 'B')
  
  players = [None] * numPlayers
  for i in xrange(numPlayers):
    player = {}
    player['index'], data = ExtractStruct(data, 'B')
    player['name'], data = ExtractString(data)
    player['score'], data = ExtractStruct(data, 'l')
    player['duration'], data = ExtractStruct(data, 'f')
    players.append(player)
    
  if len(data) != 0:
    raise MalformedPacket, 'Did not consume full packet (players)'
    
  return players
  
#-----------------------------------------------------------------------
def AskMaster(sock, master_addr, region=0xFF, filter='\\gamedir\\chivalrymedievalwarfare'):
  '''master_addr should be an AF_INET addr tuple (addr, port)
  Returns a list of tuples containing addresses of servers under this master'''
  ipList = []
  lastIp = None
  nextIp = END_OF_LIST_IP
  while True:
    
    #print "This request {0}".format(nextIp)
    request = struct.pack('!cB', '1', region) + PutString('{0}:{1}'.format(*nextIp)) + PutString(filter)
    sock.sendto(request, master_addr)
    replies = 0
    try:
      if g_GameHostIp != None:
        ip = (g_GameHostIp,int(g_GameHostPort))
        lastIp = ip
        replies += 1
        lastIp = None
       
        if (ip == END_OF_LIST_IP):
          return
        yield ip
      else:
        for ip in ParseMasterResponse(sock.recvfrom(14000)):
          lastIp = ip
          replies += 1
          if (ip == END_OF_LIST_IP):
            return
          yield ip
    except socket.timeout:
      print >> sys.stderr, "Timed out talking to master {0} after {1} replies".format(master_addr, replies)
      break
    
    if lastIp == None: # 0 responses
      return
    else: # More responses await
      nextIp = lastIp
      lastIp = None
      #print "Next request {0}".format(nextIp)
    

def AskServerForChallenge(sock, server_addr, challengeType):
  '''Helper request. Required before asking for Rules or Players.
  Not sure why!'''
  global g_malformedPackets
  if challengeType is None:
    request = STEAM_HEADER + 'W'
  else:
    request = STEAM_HEADER + challengeType + struct.pack('l', -1)
  t_locals.stream.append('S: {0}'.format(b16encode(request)))
  sock.sendto(request, server_addr)
  while True:
    try:
      return ParseChallengeResponse(ReceiveServerPackets(sock))
    except socket.timeout:
      raise Timeout
    except MalformedPacket:
      with l_data:
        g_malformedPackets += 1

def AskServerForInfo(sock, server_addr):
  global g_malformedPackets
  request = STEAM_HEADER + 'TSource Engine Query\x00'
  t_locals.stream.append('S: {0}'.format(b16encode(request)))
  sock.sendto(request, server_addr)
  while True:
    try:
      # print 'Asking for info'
      info = ParseInfoResponse(ReceiveServerPackets(sock))
    except socket.timeout:
      raise Timeout
    except MalformedPacket:
      with l_data:
        g_malformedPackets += 1
      continue 
    return info
  
def AskServerForRules(sock, server_addr):
  global g_malformedPackets
  try:
    challenge = AskServerForChallenge(sock, server_addr, 'V')
  except Timeout:
    challenge = AskServerForChallenge(sock, server_addr, None)
  request = STEAM_HEADER + 'V' + struct.pack('l', challenge)
  while True:
    try:
      #print 'Asking for rules'
      t_locals.stream.append('S: {0}'.format(b16encode(request)))
      sock.sendto(request, server_addr)
      info = ParseRulesResponse(ReceiveServerPackets(sock))
    except socket.timeout:
      raise Timeout
    except MalformedPacket:
      with l_data:
        g_malformedPackets += 1
      continue
    return info
  
def AskServerForPlayers(sock, server_addr):
  try:
    challenge = AskServerForChallenge(sock, server_addr, 'U')
  except Timeout:
    challenge = AskServerForChallenge(sock, server_addr, None)
  request = STEAM_HEADER + 'U' + struct.pack('l', challenge)
  while True:
    try:
      #print 'Asking for players'
      t_locals.stream.append('S: {0}'.format(b16encode(request)))
      sock.sendto(request, server_addr)
      info = ParsePlayersResponse(ReceiveServerPackets(sock))
    except socket.timeout:
      raise Timeout
    except MalformedPacket:
      with l_data:
        g_malformedPackets += 1
      continue
    return info

def GetFullServerInfo(sock, server_addr, server):
  server['info'] = AskServerForInfo(sock, server_addr)
  # Filter out servers we don't actually want.
  if server['info']['folder'] != 'chivalrymedievalwarfare':
    raise DifferentGame
  server['players'] = AskServerForPlayers(sock, server_addr)
  server['rules'] = AskServerForRules(sock, server_addr)
  
serverQueue = Queue.Queue()
completeQueue = Queue.Queue()
t_locals = threading.local()
g_port = 2000 # Start here (for no good reason)
def GetSocket():
  global g_port
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.settimeout(3.0)
  while True:
    with l_data:
      g_port += 1
      if g_port > 60000:
        g_port = 2000
    try:
      thisBind = ('', g_port )
      s.bind( thisBind )
      break
    except socket.error:
      pass
  t_locals.stream = []
  t_locals.stream.append('Getting new socket: ' + str(thisBind))
  return s

def QueueWorker():
  global g_serverTimeouts
  global g_unsupportedServerProtocols
  global g_differentGames
  global g_malformedPackets
  while True:
    sock = GetSocket()
    try:
      while True:
        try:
          server_addr = serverQueue.get(False)
          server = {}
          GetFullServerInfo(sock, server_addr, server)
          break
        except Queue.Empty:
          if g_startupFinished:
            return
      #print "Querying {0}".format(server_addr)
    except DifferentGame:
      with l_data:
        g_differentGames += 1
        continue
    except UnsupportedProtocol:
      with l_data:
        g_unsupportedServerProtocols += 1
    except Timeout:
      with l_data:
        g_serverTimeouts += 1
      sock = GetSocket()
    except Exception, e:
      with l_stream:
        print >> sys.stderr, ''
        print >> sys.stderr, '------------------------------ Error ------------------------------'
        print >> sys.stderr, '\n'.join([str(server_addr)] + t_locals.stream + [ '{0}:{1}'.format(type(e), e) ])
        print >> sys.stderr, '-------------------------------------------------------------------'
        print >> sys.stderr, ''
        
        ErrorDict = {}
        ErrorDict['timestamp'] = ChivDumpOutputMethods.FormatCurrentTime()
        ErrorDict['address'] = server_addr
        ErrorDict['t_locals'] = unicode(t_locals.stream)
        ErrorDict['error'] = [ '{0}:{1}'.format(type(e), e) ]
        PublishMessage(ErrorDict,g_rabbitChannel,'STEAMERROR','QUEUE_WORKER_ERROR', 'JSON')
    
    
    
    if len(server) == 0:
      # If we got no data, don't include it. There's probably no server there.
      continue
      
    # Push whatever we ended up with into the queue anyway.
    completeQueue.put((server_addr, server), True, None)
       
    
def Main():
  global g_startupFinished
  g_startupFinished = False
  global g_rabbitChannel
  g_rabbitChannel = ChivDumpOutputMethods.GetRabbitChannel(rabbitHost)
  threads = []
  for i in xrange(NUM_THREADS):
    t = threading.Thread(target=QueueWorker)
    t.daemon = True
    t.start()
    threads.append(t)
    
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.settimeout(3.0)
  s.bind( ('', 23000) )
    
  alreadyDone = {}
  repeatCount = 0
  for master in masterList:
    for serverIp in AskMaster(s, master):
      #print serverIp
      if (alreadyDone.has_key(serverIp)):
        repeatCount += 1
        if repeatCount > 100:
          break   
        continue
      alreadyDone[serverIp] = None
      
      serverQueue.put(serverIp)
  
  g_startupFinished = True
  serverStats_S3_String = ''
  while True:
    try:
      serverStats = completeQueue.get(False) , ChivDumpOutputMethods.FormatCurrentTime()
      serverStats_S3_String = json.dumps(serverStats, ensure_ascii=False) + '\n' + serverStats_S3_String
      ChivDumpOutputMethods.PublishMessage(bz2.compress(json.dumps(serverStats, ensure_ascii=False)) , g_rabbitChannel,'STEAMLOGS','SERVER_STATS_COMPRESSED_JSON','COMPRESSED_JSON')
            
    except Queue.Empty:
      if (len(threading.enumerate()) == 1):
        break
  print >> sys.stderr, ''
  print >> sys.stderr, 'Total Server Timeouts = '.rjust(40) + str(g_serverTimeouts)
  print >> sys.stderr, 'Total Unsupported Servers = '.rjust(40) + str(g_unsupportedServerProtocols)
  print >> sys.stderr, 'Total Different Games = '.rjust(40) + str(g_differentGames)
  print >> sys.stderr, ''
  ErrorMsgDict={}
  ErrorMsgDict['timestamp']= ChivDumpOutputMethods.FormatCurrentTime()
  ErrorMsgDict['g_serverTimeouts'] = g_serverTimeouts
  ErrorMsgDict['g_unsupportedServerProtocols'] = g_unsupportedServerProtocols
  ErrorMsgDict['g_differentGames']=g_differentGames
  ErrorMsgDict['g_malformedPackets']=g_malformedPackets
  ChivDumpOutputMethods.PublishMessage( json.dumps(ErrorMsgDict, ensure_ascii=False),g_rabbitChannel,'STEAMERROR', 'GLOBAL_VARS_REPORT','JSON')
  ChivDumpOutputMethods.FinishedUsingRabbit()
  #convert the list of servers into a single string to write to AWS s3
  #bucket/env/data/chiv/server-stats/YYYMMDD/hh:mm:ss-logs.txt 
  #bucket/env/data/chiv/server-errors/YYYMMDD/hh:mm:ss-logs.txt

  s3_bucket = ChivDumpOutputMethods.GetS3Bucket(g_AWSAccessKeyId,g_AWSSecretKey,g_S3BucketName)

  ChivDumpOutputMethods.WriteDataStringtoS3(b64encode(bz2.compress(serverStats_S3_String)),g_Game,'server-logs',s3_bucket)
 
  S3_string=''
  for line in ErrorMsgDict:
    S3_string = S3_string + '\n' + line + ' : ' + str(ErrorMsgDict[line])
    
  ChivDumpOutputMethods.WriteDataStringtoS3(S3_string,g_Game,'server-errors',s3_bucket)
  ChivDumpOutputMethods.FinishedUsingS3()
  
class Timeout(Exception):
  pass
  
class MalformedPacket(Exception):
  pass
  
class DifferentGame(Exception):
  pass
  
class UnsupportedProtocol(Exception):
  pass
  
if __name__=='__main__':
  
  Main()
