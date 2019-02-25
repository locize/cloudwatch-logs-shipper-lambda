import gzip
import json
import logging
import os

from shipper import LogzioShipper
from StringIO import StringIO

# set logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _extract_aws_logs_data(event):
    # type: (dict) -> dict
    try:
        logs_data_decoded = event['awslogs']['data'].decode('base64')
        logs_data_unzipped = gzip.GzipFile(fileobj=StringIO(logs_data_decoded)).read()
        logs_data_dict = json.loads(logs_data_unzipped)
        return logs_data_dict
    except ValueError as e:
        logger.error("Got exception while loading json, message: {}".format(e))
        raise ValueError("Exception: json loads")

def extract(msg, fromStr, toStr, convert):
    start = msg.index(fromStr) + len(fromStr)
    end = msg.rfind(toStr)
    part = msg[start:end]
    if convert:
        return int(float(part))
    return part

def _parse_cloudwatch_log(log, aws_logs_data, log_type):
    # type: (dict, dict) -> None
    if '@timestamp' not in log:
        log['@timestamp'] = str(log['timestamp'])
        del log['timestamp']

    log['message'] = log['message'].replace('\n', '')
    log['logStream'] = aws_logs_data['logStream']
    log['messageType'] = aws_logs_data['messageType']
    log['owner'] = aws_logs_data['owner']
    log['logGroup'] = aws_logs_data['logGroup']
    log['function_version'] = aws_logs_data['function_version']
    log['invoked_function_arn'] = aws_logs_data['invoked_function_arn']
    log['type'] = log_type

    # If FORMAT is json treat message as a json
    try:
        if os.environ['FORMAT'].lower() == 'json':
            splitted = log['message'].split('\t')
            skipJSONParsing = log['message'].startswith('START') \
                    or log['message'].startswith('END') \
                    or log['message'].startswith('REPORT')
            if len(splitted) > 2 and splitted[2].startswith("{") and splitted[2].endswith("}"):
                json_object = json.loads(splitted[2])
                log['requestId'] = splitted[1]
            else:
                if skipJSONParsing:
                    splitted2 = log['message'].replace('\t', ' ').split(' ')
                    log['requestId'] = splitted2[2]
                    if log['message'].startswith('REPORT'):
                        log['duration'] = extract(log['message'], 'Duration: ', ' ms	Billed', True)
                        log['memorySize'] = extract(log['message'], 'Memory Size: ', ' MB	Max', True)
                        log['memoryUsed'] = extract(log['message'], 'Max Memory Used: ', ' MB', True)
                json_object = json.loads(log['message'])
            for key, value in json_object.items():
                log[key] = value
    except (KeyError, ValueError):
        pass


def _enrich_logs_data(aws_logs_data, context):
    # type: (dict, 'LambdaContext') -> None
    try:
        aws_logs_data['function_version'] = context.function_version
        aws_logs_data['invoked_function_arn'] = context.invoked_function_arn
    except KeyError:
        pass


def lambda_handler(event, context):
    # type: (dict, 'LambdaContext') -> None
    try:
        logzio_url = "{0}/?token={1}".format(os.environ['URL'], os.environ['TOKEN'])
        log_type = (os.environ['TYPE'])
    except KeyError as e:
        logger.error("Missing one of the environment variable: {}".format(e))
        raise

    aws_logs_data = _extract_aws_logs_data(event)
    _enrich_logs_data(aws_logs_data, context)
    shipper = LogzioShipper(logzio_url)

    logger.info("About to send {} logs".format(len(aws_logs_data['logEvents'])))
    for log in aws_logs_data['logEvents']:
        if not isinstance(log, dict):
            raise TypeError("Expected log inside logEvents to be a dict but found another type")

        _parse_cloudwatch_log(log, aws_logs_data, log_type)
        shipper.add(log)

    shipper.flush()
