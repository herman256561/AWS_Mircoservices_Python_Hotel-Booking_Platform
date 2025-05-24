import os
import io
import jwt
import json
import uuid
import boto3
import base64
import logging
import traceback
import multipart as python_multipart


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def parse_form(headers, body, boundary):
    fields, files = {}, {}

    def on_field(field):
        key = field.field_name.decode()
        value = field.value.decode()
        fields[key] = value

    def on_file(file):
        key = file.field_name.decode()
        files[key] = file

    headers['Content-Type'] = headers['content-type']
    
    content_type = headers.get('content-type')
    if content_type is None:
        logging.getLogger(__name__).warning("Your header misses Content-Type")
        raise ValueError("Your header misses Content-Type")

    # Extract the multipart/form-data part and remove whitespace
    content_type_part = content_type.split(';')[0].strip()
    boundary_part = content_type.split(';')[1].strip()

    # Update the headers with the modified Content-Type value
    new_headers = {}
    new_headers['Content-Type'] = content_type_part+';'+boundary_part
    
    python_multipart.parse_form(headers=new_headers, input_stream=body, on_field=on_field, on_file=on_file)
    return fields, files


def handler(event, context):
    logger.info('Processing request')
    
    response_headers = {
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "*"
    }
    
    # Handle preflight OPTIONS request
    if event.get('httpMethod') == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': response_headers,
            'body': json.dumps({'message': 'Preflight request successful'})
        }
    
    try:
        request_headers = event['headers']
        # Convert headers to lowercase for case-insensitive lookup
        lowercase_headers = {k.lower(): v for k, v in request_headers.items()}
        request_headers['content-type'] = lowercase_headers.get('content-type', '')
        
        logger.info(f"Headers: {json.dumps(request_headers)}")
        
        body = event['body']
        
        if bool(event.get('isBase64Encoded')):
            body = base64.b64decode(body)
        else:
            body = body.encode('utf-8')
        
        logger.info(f"Body length: {len(body)} bytes")
        
        boundary = extract_boundary(request_headers)
        logger.info(f"Boundary: {boundary}")
        
        fields, files = parse_form(request_headers, io.BytesIO(body), boundary)
        
        logger.info(f"Parsed fields: {list(fields.keys())}")
        logger.info(f"Field values: {json.dumps({k: v for k, v in fields.items()})}")
        logger.info(f"Parsed files: {list(files.keys())}")

        # Extract form fields
        hotel_name = fields.get('hotelName')
        hotel_rating = fields.get('hotelRating')
        hotel_city = fields.get('hotelCity')
        hotel_price = fields.get('hotelPrice')
        
        # Get userId from the form - try both 'userId' and alternative field names
        user_id = fields.get('userId')
        logger.info(f"userId field value: {user_id}")
        
        # Fallback to currentUserId if userId is empty
        if not user_id:
            user_id = fields.get('currentUserId')
            logger.info(f"currentUserId field value: {user_id}")
        
        # As a last resort, create a random userId if needed
        if not user_id:
            user_id = str(uuid.uuid4())
            logger.info(f"Generated random userId: {user_id}")
        
        id_token = fields.get('idToken')
        
        # Check required fields
        required_fields = {
            'Hotel Name': hotel_name,
            'Hotel Rating': hotel_rating,
            'Hotel City': hotel_city,
            'Hotel Price': hotel_price,
            'ID Token': id_token
        }
        
        missing_fields = [field for field, value in required_fields.items() if not value]
        if missing_fields:
            return {
                'statusCode': 400,
                'headers': response_headers,
                'body': json.dumps({
                    'Error': f'Missing required fields: {", ".join(missing_fields)}'
                })
            }

        file = files.get('photo')
        if not file:
            return {
                'statusCode': 400,
                'headers': response_headers,
                'body': json.dumps({
                    'Error': 'Missing photo file'
                })
            }
            
        file_name = file.file_name.decode()
        file.file_object.seek(0)
        file_content = file.file_object.read()
        
        logger.info(f"File name: {file_name}")
        logger.info(f"File size: {len(file_content)} bytes")
        
        # Performing Authorization.
        # Authorization must be done at API Gateway Level using a Custom Lambda Authorizer
        # In this code it is done in the microservice for educational purposes
        
        token = jwt.decode(id_token, options={"verify_signature": False})
        group = token.get('cognito:groups')
        
        logger.info(f"User groups: {group}")

        if group is None or 'Admin' not in group:
            return {
                'statusCode': 401,
                'headers': response_headers,
                'body': json.dumps({
                    'Error': 'You are not a member of the Admin group'
                })
            }

        bucket_name = os.environ.get('bucketName')
        region = os.environ.get('AWS_REGION')
        
        logger.info(f"Bucket name: {bucket_name}, Region: {region}")
        
        # Initialize clients outside the try block to catch initialization errors
        s3_client = boto3.client('s3', region_name=region)
        dynamoDb = boto3.resource('dynamodb', region_name=region)
        table = dynamoDb.Table('Hotels')
        sns_client = boto3.client('sns')
        
        # Describe the table to see its structure
        try:
            table_description = dynamoDb.meta.client.describe_table(TableName='Hotels')
            key_schema = table_description['Table']['KeySchema']
            logger.info(f"Table key schema: {json.dumps(key_schema)}")
        except Exception as e:
            logger.warning(f"Could not describe table: {str(e)}")

        try:
            # Upload the image to S3
            logger.info(f"Uploading to S3: {file_name}")
            file.file_object.seek(0)  # Reset file position before reading again
            s3_response = s3_client.put_object(
                Bucket=bucket_name,
                Key=file_name,
                Body=file.file_object.read()
            )
            logger.info(f"S3 upload complete: {s3_response}")
            
            # Generate a unique ID for the hotel
            hotel_id = str(uuid.uuid4())
        
            # Create hotel record with ALL possible variations of primary key fields
            hotel = {
                "userid": user_id,      # all lowercase
                "id": hotel_id,         # all lowercase id
                "Id": hotel_id,         # Pascal case
                "ID": hotel_id,         # all uppercase
                "Name": hotel_name,
                "CityName": hotel_city,
                "Price": int(hotel_price),
                "Rating": int(hotel_rating),
                "FileName": file_name
            }
            
            logger.info(f"Writing to DynamoDB with item: {json.dumps(hotel)}")
            # Store the hotel record in DynamoDb
            table.put_item(Item=hotel)
            logger.info("DynamoDB write complete")

            # Publish event to SNS
            sns_arn = os.environ.get("hotelCreationTopicArn")
            sns_client.publish(
                TopicArn = sns_arn,
                Message = json.dumps(hotel)
            )
            
        except Exception as e:
            error_msg = str(e)
            stack_trace = traceback.format_exc()
            logger.error(f"Error in AWS operations: {error_msg}")
            logger.error(f"Stack trace: {stack_trace}")
            return {
                "statusCode": 500,
                'headers': response_headers,
                "body": json.dumps({
                    "Error": error_msg
                })
            }
        
        logger.info("Request processing completed successfully")
        return {
            'statusCode': 200,
            'headers': response_headers,
            'body': json.dumps({"message": "ok"})
        }
        
    except Exception as e:
        error_msg = str(e)
        stack_trace = traceback.format_exc()
        logger.error(f"Unexpected error: {error_msg}")
        logger.error(f"Stack trace: {stack_trace}")
        return {
            'statusCode': 500,
            'headers': response_headers,
            'body': json.dumps({
                "Error": error_msg
            })
        }

    
def extract_boundary(headers):
    content_type = headers.get('content-type', '')
    boundary_start = content_type.find('boundary=')
    if boundary_start != -1:
        boundary_end = content_type.find(';', boundary_start)
        if boundary_end == -1:
            boundary_end = len(content_type)
        boundary = content_type[boundary_start + len('boundary='):boundary_end].strip()

        # Check if the boundary is enclosed in quotes and remove them if present
        if boundary.startswith('"') and boundary.endswith('"'):
            boundary = boundary[1:-1]

        return boundary

    return None