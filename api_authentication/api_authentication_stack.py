import aws_cdk as cdk
from aws_cdk import (
    aws_lambda as _lambda,
    aws_apigateway as apigateway,
    aws_ecr as ecr,
    Stack,
    Fn,
    aws_iam as iam
)

import os
from constructs import Construct


class ApiAuthenticationStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        

        # Define the Lambda function using DockerImageCode
        self.lambda_function = _lambda.DockerImageFunction(
            self, "APIAuthentication",
            code=_lambda.DockerImageCode.from_image_asset(
               "./DockerLambda"
            ),
            function_name="APIAuthentication",
            
            timeout=cdk.Duration.seconds(60),
            memory_size=1024,
            environment={
                "PATH": "/opt/lambda"
            }
        )

        # # Import existing API Gateway
        # api = apigateway.RestApi.from_rest_api_attributes(self, 'Be-configurator-PublicAPI',
        #     rest_api_id='9dk0lti9o6',
        #     root_resource_id='ggoyrol'
        # )

        # # Add Lambda integration to existing API
        # lambda_integration = apigateway.LambdaIntegration(self.lambda_function)
        # api.root.add_resource('authenticate').add_method('GET', lambda_integration)
        
