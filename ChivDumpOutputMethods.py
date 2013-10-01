import pika
from boto.s3.connection import S3Connection, Location, Key
from time import strftime, gmtime
from datetime import datetime, date, time 

rabbitConnections = []
S3Connections = []

def FormatCurrentTime():
  return strftime("%Y-%m-%d %H:%M:%S", gmtime())

def GetRabbitChannel(rabbitHost):
  connection = pika.BlockingConnection(pika.ConnectionParameters(rabbitHost, 5672))  
  rabbitConnections.append(connection)
  return connection.channel()

def FinishedUsingRabbit():
  for conn in rabbitConnections:
    conn.close()

def PublishMessage(msg,rabbitChannel,exchange,HeaderType,HeaderMessageFormat): 
    properties = pika.spec.BasicProperties(headers={
                                                    'type': HeaderType,
                                                     'format': HeaderMessageFormat,
                                                    'PublishTimestamp': FormatCurrentTime(),
                                                    }
                                           )   
    rabbitChannel.basic_publish(exchange=exchange,
                  routing_key='',
                  properties=properties,
                  body=msg) 
   
def GetS3Bucket(AWSAccessKeyId,AWSSecretKey, S3_Bucket):
  conn = S3Connection(AWSAccessKeyId, AWSSecretKey)
  S3Connections.append(conn)
  return conn.get_bucket(S3_Bucket)

def FinishedUsingS3():
  for conn in S3Connections:
    conn.close()

def WriteDataStringtoS3(string,game,msg_type, S3_bucket): 
  
  today_YYYMMDD, today_hhmmss = datetime.now().strftime('%Y%m%d') , datetime.now().strftime('%H-%M-%S')    
  S3_path =  '/data/' + game + '/' + msg_type + '/' +  today_YYYMMDD +  '/' +  today_hhmmss + '-logs.txt' 
  
  k=Key(S3_bucket)
  k.key = S3_path  
  k.set_contents_from_string(string,reduced_redundancy=True)  

