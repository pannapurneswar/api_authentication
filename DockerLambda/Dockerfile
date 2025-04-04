FROM amazon/aws-lambda-python:latest




# Copies requirements.txt file into the container
COPY requirements.txt ./
# Installs dependencies found in your requirements.txt file
RUN pip install -r requirements.txt

# Be sure to copy over the function itself!
# Goes last to take advantage of Docker caching.
COPY AWSAuthLambdaContainerFunction.py ./

# Points to the handler function of your lambda function
CMD ["AWSAuthLambdaContainerFunction.lambda_handler"]
