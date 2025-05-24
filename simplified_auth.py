import json
import boto3
import base64
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def decode_jwt(token):
    """Decode JWT token without verification"""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT format")
    
    # Decode header and payload
    def decode_part(part):
        # Add padding if needed
        padding = "=" * (4 - (len(part) % 4))
        if padding == 4:
            padding = ""
        part = part.replace("-", "+").replace("_", "/")
        return json.loads(base64.b64decode(part + padding).decode("utf-8"))
    
    return {
        "header": decode_part(parts[0]),
        "payload": decode_part(parts[1])
    }

def auth(event, context):
    try:
        logger.info(f"Auth event received: {json.dumps(event)}")
        
        # Get token from query parameters, or fall back to Authorization header
        id_token = None
        token_source = "unknown"
        
        if 'queryStringParameters' in event and event.get('queryStringParameters') and 'token' in event.get('queryStringParameters', {}):
            id_token = event['queryStringParameters']['token']
            token_source = "query_string"
        elif 'authorizationToken' in event:
            id_token = event['authorizationToken']
            token_source = "authorization_token"
        elif 'headers' in event and event.get('headers') and 'Authorization' in event.get('headers', {}):
            auth_header = event['headers']['Authorization']
            id_token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else auth_header
            token_source = "authorization_header"
        
        logger.info(f"Token source: {token_source}")
        
        if not id_token:
            logger.error("No token found in the request")
            return create_deny_policy(event['methodArn'], "No token provided")
        
        logger.info(f"Token retrieved from {token_source} (first 20 chars): {id_token[:20]}...")
        
        # Decode token without verification
        try:
            token_data = decode_jwt(id_token)
            header = token_data["header"]
            payload = token_data["payload"]
            
            logger.info(f"Token header: {json.dumps(header)}")
            logger.info(f"Token payload: {json.dumps(payload)}")
        except Exception as e:
            logger.error(f"Error decoding token: {str(e)}")
            return create_deny_policy(event['methodArn'], "Error decoding token")
        
        # Extract user ID
        user_id = payload.get('sub')
        if not user_id:
            logger.error("No 'sub' claim found in token")
            return create_deny_policy(event['methodArn'], "No sub claim in token")
        
        # Prepare response
        response = {
            "principalId": user_id,
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": "Allow",
                        "Resource": event['methodArn']
                    }
                ]
            },
            "context": {
                "userId": user_id
            }
        }
        
        # Check path and group permissions
        path = ""
        if 'path' in event:
            path = event['path']
        elif 'resource' in event:
            path = event['resource']
        elif 'requestContext' in event and 'resourcePath' in event['requestContext']:
            path = event['requestContext']['resourcePath']
        
        logger.info(f"Request path: {path}")
        
        # Use both versions of the mapping to be safe
        api_group_mapping = {
            "listadminhotels": "Admin",
            "listadminhotel": "Admin",
            "admin": "Admin"
        }
        
        # Check if path contains any of the keys
        expected_group = None
        for key, group in api_group_mapping.items():
            if key in path:
                expected_group = group
                logger.info(f"Path contains '{key}', requiring group: {group}")
                break
        
        logger.info(f"Expected group: {expected_group}")
        
        # Check user groups if a group is expected
        if expected_group:
            user_groups = payload.get('cognito:groups', [])
            if not isinstance(user_groups, list):
                user_groups = [user_groups]
                
            logger.info(f"User groups: {user_groups}")
            
            if expected_group not in user_groups:
                logger.info(f"Access denied: User not in required group {expected_group}")
                response['policyDocument']['Statement'][0]['Effect'] = "Deny"
        
        logger.info(f"Returning policy: {json.dumps(response)}")
        return response
        
    except Exception as e:
        logger.error(f"Unhandled exception: {str(e)}")
        return create_deny_policy(event['methodArn'], f"Error: {str(e)}")

def create_deny_policy(method_arn, reason):
    """Create a deny policy with reason in context"""
    policy = {
        "principalId": "user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Deny",
                    "Resource": method_arn
                }
            ]
        },
        "context": {
            "reason": reason
        }
    }
    logger.info(f"Returning deny policy: {json.dumps(policy)}")
    return policy