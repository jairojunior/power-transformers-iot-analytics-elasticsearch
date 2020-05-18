import logging
import sys
import boto3
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)
streamHandler = logging.StreamHandler(stream=sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
streamHandler.setFormatter(formatter)
logger.addHandler(streamHandler)

client = boto3.client('dynamodb')

def handler(event, context):
    logger.info("event before processing: {}".format(event))

    for e in event:
        name = e['id']

        response = client.get_item(TableName=os.environ('TABLE_NAME'), Key={'name': {'S': name}})
        item = response['Item']

        e['MonthsOfUsage'] = int(item['monthsOfUsage']['N'])

        e['lat'] = float(item['lat']['N'])
        e['lon'] = float(item['lon']['N'])

        logger.info("event after processing: {}".format(event))

    return event