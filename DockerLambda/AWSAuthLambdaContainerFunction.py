import json
import requests
import logging
import base64
import hmac
import hashlib

# Set the logging configuration
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create a custom formatter
formatter = logging.Formatter('%(asctime)s - %(filename)s - %(levelname)s - %(message)s')


# Create a handler and attach the formatter to it
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)



def lambda_handler(event, context):
    #aws_lambda_logging.setup(level='INFO')
    
    # Create a custom log record in JSON format
    print(event)
    custom_log_msg_json={
        "username":"",
        "routeKey":event['routeKey'].lower(),
        "lambda_function":"AWSAPIAuthenticationService",
       
        "log_label":"",
        "log_message":""
    }
        
    
    
    try:
    #Get the body of the POST request
        
        authorizationHeader = event["headers"].get("authorization")
        clientId=event["headers"].get("clientid")
        clientsecret=event["headers"].get("clientsecret")
        if authorizationHeader is None or authorizationHeader=="":
            errormsg={"errormessage":"Authorization Header missing or not set"}
            custom_log_msg_json["log_label"]="Error_Message"
            custom_log_msg_json["log_message"]=str(errormsg)
            logger.error(str(custom_log_msg_json))
            
            return {
                    "statusCode": 400,
                    "body":  json.dumps(errormsg)
            } 
        if clientId is None or clientId=="":
            errormsg={"errormessage":"clientId is missing in Header"}
            custom_log_msg_json["log_label"]="Error_Message"
            custom_log_msg_json["log_message"]=str(errormsg)
            logger.error(str(custom_log_msg_json))
            
            return {
                    "statusCode": 400,
                    "body":  json.dumps(errormsg)
            } 
        
        encodedCreds = authorizationHeader.split(' ')[1]
        username, password = base64.b64decode(
                        encodedCreds).decode().split(':')
        logger.info('**** Start **')
        
        
        #Check for Client Errors like NULL or blank username ,password and client id'''
        if username is None or username=='' or password is None or password==''  or clientId is None or clientId=='':
            errormsg={"errormessage":"username or password or client id is mandatory"}
            custom_log_msg_json["log_label"]="Error_Message"
            custom_log_msg_json["log_message"]=str(errormsg)
            logger.error(str(custom_log_msg_json))
            return {
                     "statusCode": 400,
                    "body":  json.dumps(errormsg)
            } 
        # Create message and key bytes
        message, key = (username + clientId).encode('utf-8'), clientsecret.encode('utf-8')

        # Calculate secret hash
        secret_hash = base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode()


        url="https://cognito-idp.us-west-2.amazonaws.com/"
        request_body= {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters":{
            "USERNAME": username,
            "PASSWORD": password,
            'SECRET_HASH': secret_hash
            },
            "ClientId": clientId
            }
        headers={'X-Amz-Target':'AWSCognitoIdentityProviderService.InitiateAuth','Content-Type':'application/x-amz-json-1.1'}
        
        response = requests.post(url ,data=json.dumps(request_body),headers=headers)
        #log.debug('Payload Received from Congito API:',response.json())
        
        custom_log_msg_json["log_label"]="Payload from Cognito"
        custom_log_msg_json["log_message"]=str(response.json())
        logger.debug(str(custom_log_msg_json))
        resp_msg=response.json()
        if resp_msg.get("__type") is not None:
            message=resp_msg.get("message")
            errormsg = {"errormessage": resp_msg.get("message")}
            custom_log_msg_json["log_label"]="Error_Message"
            custom_log_msg_json["log_message"]=str(errormsg)
            logger.error(str(custom_log_msg_json))
            return {
                "statusCode": 400,
                'headers': {
            
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
                "body": json.dumps(errormsg)
            }
    except requests.RequestException as e:
        custom_log_msg_json["log_label"]="Error_Message"
        custom_log_msg_json["log_message"]=str(e)
        logger.error(str(custom_log_msg_json))
        errormsg = {"errormessage": "Something wrong..Please contact  administrator"}
        return  {
            "statusCode": 500,
            'headers': {
            
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
            "body": json.dumps(errormsg)
        }
    
    logging.info('**** End   - Return Success**')
    custom_log_msg_json["log_label"]="Response to API request"
    custom_log_msg_json["log_message"]=str(response.json())
    logger.debug(str(custom_log_msg_json))
    #Success message
    return {
        "statusCode": 200,
        'headers': {
            
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        },
        "body":  json.dumps(response.json())
    }
   
   
