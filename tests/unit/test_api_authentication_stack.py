import aws_cdk as core
import aws_cdk.assertions as assertions

from api_authentication.api_authentication_stack import ApiAuthenticationStack

# example tests. To run these tests, uncomment this file along with the example
# resource in api_authentication/api_authentication_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = ApiAuthenticationStack(app, "api-authentication")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
