import json
import os
import boto3
import jwt # pyJwt
from http import HTTPStatus
from typing import Any, Dict, List
from boto3.dynamodb.conditions import Key
from dynamodb_json import json_util as ddb_json
import traceback

def handler(event, context):    
    # Log the entire incoming event
    print("RECEIVED EVENT: " + json.dumps(event, default=str))
    print("CONTEXT: " + str(context))
    
    try:
        # Check if queryStringParameters exists
        if not event.get("queryStringParameters"):
            print("ERROR: queryStringParameters is None or empty")
            return create_error_response("Missing query parameters", HTTPStatus.BAD_REQUEST)
        
        # Log query parameters
        print("QUERY PARAMETERS: " + json.dumps(event.get("queryStringParameters", {})))
        
        # Get token and validate
        token = event.get("queryStringParameters", {}).get("token")
        print("TOKEN RECEIVED: " + (str(token) if token else "None"))
        
        if not token:
            print("ERROR: Token is missing")
            return create_error_response("Query string parameter 'token' is missing", HTTPStatus.BAD_REQUEST)
        
        # Decode token
        print("DECODING TOKEN...")
        try:
            token_details = jwt.decode(token, options={"verify_signature":False})
            print("TOKEN DECODED SUCCESSFULLY: " + json.dumps(token_details, default=str))
        except Exception as e:
            print(f"TOKEN DECODE ERROR: {str(e)}")
            print(traceback.format_exc())
            return create_error_response(f"Invalid token format: {str(e)}", HTTPStatus.BAD_REQUEST)
        
        # Get user ID
        user_id = token_details.get("sub")
        print(f"USER ID FROM TOKEN: {user_id}")
        
        if not user_id:
            print("ERROR: No user_id (sub) found in token")
            return create_error_response("Token does not contain 'sub' claim", HTTPStatus.BAD_REQUEST)
        
        # Initialize DynamoDB
        region = os.environ.get("AWS_REGION")
        print(f"USING AWS REGION: {region}")
        
        print("INITIALIZING DYNAMODB CLIENT...")
        db_client = boto3.resource("dynamodb", region_name=region)
        
        # Get table
        table_name = "Hotels"
        print(f"ACCESSING DYNAMODB TABLE: {table_name}")
        table = db_client.Table(table_name)
        
        # Scan table
        print(f"SCANNING TABLE WITH FILTER: userid = {user_id}")
        try:
            scan_response = table.scan(
                FilterExpression=Key("userid").eq(user_id)
            )
            print(f"SCAN COMPLETE. FOUND {len(scan_response.get('Items', []))} ITEMS")
            print(f"SCAN RESPONSE: {json.dumps(scan_response, default=str)}")
        except Exception as e:
            print(f"DYNAMODB SCAN ERROR: {str(e)}")
            print(traceback.format_exc())
            return create_error_response(f"DynamoDB error: {str(e)}", HTTPStatus.INTERNAL_SERVER_ERROR)
        
        # Process results
        print("PROCESSING RESULTS...")
        try:
            hotels = ddb_json.loads(scan_response.get("Items", []))
            print(f"PROCESSED {len(hotels)} HOTELS")
            # Log first hotel for debugging (if any exist)
            if hotels and len(hotels) > 0:
                print(f"SAMPLE HOTEL: {json.dumps(hotels[0], default=str)}")
        except Exception as e:
            print(f"JSON PROCESSING ERROR: {str(e)}")
            print(traceback.format_exc())
            return create_error_response(f"Error processing DynamoDB results: {str(e)}", HTTPStatus.INTERNAL_SERVER_ERROR)
        
        # Create successful response
        response = {
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "OPTIONS, GET"
            },
            "body": json.dumps({"Hotels": hotels}),
            "statusCode": HTTPStatus.OK,
        }
        
        print("RETURNING SUCCESSFUL RESPONSE")
        print(f"RESPONSE: {json.dumps(response, default=str)}")
        return response
        
    except Exception as e:
        print(f"UNHANDLED EXCEPTION: {str(e)}")
        print(traceback.format_exc())
        return create_error_response(f"Internal server error: {str(e)}", HTTPStatus.INTERNAL_SERVER_ERROR)

def create_error_response(message, status_code):
    """Helper function to create error responses with consistent structure"""
    response = {
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "OPTIONS, GET"
        },
        "body": json.dumps({"Error": message}),
        "statusCode": status_code,
    }
    print(f"ERROR RESPONSE: {json.dumps(response, default=str)}")
    return response