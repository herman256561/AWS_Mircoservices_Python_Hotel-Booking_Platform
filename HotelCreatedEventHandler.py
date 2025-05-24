import json
import os
import boto3
from boto3 import dynamodb
import traceback
import urllib3
import base64

def handler(event, context):

    message_id = event['Records'][0]['Sns']["MessageId"]
    sns_message = event['Records'][0]['Sns']["Message"]
    sns_message_json = json.loads(sns_message)

    tableName = os.environ.get("hotelCreatedEventIdsTable")

    dynamodb_client = boto3.client('dynamodb')

    try:
        dynamodb_client.describe_table(TableName=tableName)
    except dynamodb_client.exceptions.ResourceNotFoundException:
        raise Exception(f"You must create the table {tableName} in DynamoDB (in AWS).")

    response = dynamodb_client.get_item(
        TableName = tableName,
        Key={
            "eventId":{"S": message_id}
        }
    )

    if 'Items' not in response:
        dynamodb_client.put_item(
            TableName=tableName,
            Item={
                "eventId":{
                    "S": message_id
                }
            }
        )
        
        # OpenSearch configuration with username/password
        host = os.getenv("host")  # OpenSearch domain endpoint
        username = os.getenv("userName")  # OpenSearch master username
        password = os.getenv("password")  # OpenSearch master password
        index_name = os.getenv("indexName")
        
        # Prepare the document URL and data
        url = f"{host}/{index_name}/_doc/{sns_message_json['Id']}"
        
        # Create basic auth header
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic {encoded_credentials}'
        }
        
        # Send the request using urllib3
        http = urllib3.PoolManager()
        response = http.request(
            method='PUT',
            url=url,
            body=json.dumps(sns_message_json),
            headers=headers
        )
        
        print(f"OpenSearch indexing response: {response.status}")
        if response.status not in [200, 201]:
            print(f"Error indexing document: {response.data.decode('utf-8')}")
            raise Exception(f"Failed to index document in OpenSearch: {response.status}")
        
    return {
        'statusCode': 200,
        'body': json.dumps('Hotel creation event processed successfully')
    }