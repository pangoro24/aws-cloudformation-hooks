import json
import logging
from typing import Any, Dict, Tuple, List

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SUCCESS = "SUCCESS"
FAILED = "FAILED"

def validate_target_type(target_type: str) -> bool:
    """
    Validates if the target type is supported by this hook
    Args:
        target_type: The resource type to validate
    Returns:
        bool: True if the target type is supported, False otherwise
    """
    try:
        return target_type == "AWS::S3::Bucket"
    except Exception as e:
        logger.error(f"Error validating target type: {str(e)}")
        return False

def evaluate_bucket_compliance(properties: Dict[str, Any]) -> Tuple[str, str, List[Dict[str, Any]]]:
    """
    Evaluates if the S3 bucket complies with public access block requirements
    Args:
        properties: Dictionary containing the bucket properties
    Returns:
        tuple: (status, message, annotations) where:
            - status is SUCCESS or FAILED
            - message is the main message
            - annotations is a list of annotation objects with remediation details
    """
    try:
        public_access_block_configuration = properties.get('PublicAccessBlockConfiguration', {})
        
        # Check if PublicAccessBlockConfiguration is present and all settings are True
        required_settings = {
            'BlockPublicAcls': True,
            'BlockPublicPolicy': True,
            'IgnorePublicAcls': True,
            'RestrictPublicBuckets': True
        }

        if not public_access_block_configuration:
            # Create annotation for failed compliance check
            annotation = {
                "annotationName": "S3PublicAccessBlockCompliance",
                "status": "FAILED",
                "statusMessage": "PublicAccessBlockConfiguration is required for S3 buckets",
                "remediationMessage": "Must remove public access at a bucket level",
                "remediationLink": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                "severityLevel": "HIGH"
            }
            return FAILED, "PublicAccessBlockConfiguration is required for S3 buckets", [annotation]

        failed_settings = []
        for setting, required_value in required_settings.items():
            if public_access_block_configuration.get(setting) != required_value:
                failed_settings.append(setting)

        if failed_settings:
            # Create annotation for failed settings
            annotation = {
                "annotationName": "S3PublicAccessBlockCompliance",
                "status": "FAILED",
                "statusMessage": f"S3 bucket must have the following settings enabled: {', '.join(failed_settings)}",
                "remediationMessage": "Must remove public access at a bucket level",
                "remediationLink": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                "severityLevel": "HIGH"
            }
            return FAILED, f"S3 bucket must have {', '.join(failed_settings)} set to True", [annotation]

        # All checks passed
        annotation = {
            "annotationName": "S3PublicAccessBlockCompliance",
            "status": "PASSED",
            "statusMessage": "S3 bucket complies with public access block requirements",
            "remediationMessage": None,
            "remediationLink": None,
            "severityLevel": "HIGH"
        }
        return SUCCESS, "S3 bucket complies with public access block requirements", [annotation]
    except Exception as e:
        logger.error(f"Error evaluating bucket compliance: {str(e)}")
        annotation = {
            "annotationName": "S3PublicAccessBlockCompliance",
            "status": "FAILED",
            "statusMessage": f"Error evaluating bucket configuration: {str(e)}",
            "remediationMessage": "Must remove public access at a bucket level",
            "remediationLink": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            "severityLevel": "HIGH"
        }
        return FAILED, f"Error evaluating bucket configuration: {str(e)}", [annotation]

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler function for the CloudFormation hook
    Args:
        event: Lambda event object
        context: Lambda context object
    Returns:
        Dict: Response object containing the validation result with annotations
    """
    client_request_token = event.get("clientRequestToken") or event.get("clientRequesttoken") if isinstance(event, dict) else None
    try:
        # Extract logging variables early
        target_logical_id = event.get("requestData", {}).get("targetLogicalId")
        action_invocation_point = event.get("actionInvocationPoint")
        invocation = event.get("requestContext", {}).get("invocation")
        callback_context = event.get("requestContext", {}).get("callbackContext")

        logger.info(
            f"Received event - TargetLogicalId: {target_logical_id}, "
            f"ActionInvocationPoint: {action_invocation_point}, "
            f"Invocation: {invocation}. Event details: {event}"
        )

        # Extract required information from the event
        target_type = event.get("requestData", {}).get('targetType')
        
        # Validate target type
        if not validate_target_type(target_type):
            response = {
                "hookStatus": FAILED,
                "errorCode": "NonCompliant",
                "message": f"Unsupported resource type: {target_type}",
                "clientRequestToken": client_request_token,
                "callbackContext": callback_context,
                "callbackDelaySeconds": 0,
                "annotations": [{
                    "annotationName": "S3PublicAccessBlockCompliance",
                    "status": "FAILED",
                    "statusMessage": f"Unsupported resource type: {target_type}",
                    "remediationMessage": "Must remove public access at a bucket level",
                    "remediationLink": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                    "severityLevel": "HIGH"
                }]
            }
            logger.info(f"Validation result for {target_logical_id} (Invocation: {invocation}): {response}")
            return response

        resource_properties = event.get("requestData", {}).get("targetModel", {}).get('resourceProperties', {})

        # Evaluate bucket compliance
        status, message, annotations = evaluate_bucket_compliance(resource_properties)

        response = {
            "hookStatus": status,
            "errorCode": "NonCompliant" if status == FAILED else None,
            "message": message,
            "clientRequestToken": client_request_token,
            "callbackContext": callback_context,
            "callbackDelaySeconds": 0,
            "annotations": annotations
        }

        logger.info(f"Validation result for {target_logical_id} (Invocation: {invocation}): {response}")
        return response

    except Exception as e:
        error_message = f"Unexpected error in hook execution: {str(e)}"
        logger.error(error_message)
        return {
            "hookStatus": FAILED,
            "errorCode": "InternalFailure",
            "message": error_message,
            "clientRequestToken": client_request_token,
            "callbackContext": None,
            "callbackDelaySeconds": 0,
            "annotations": [{
                "annotationName": "S3PublicAccessBlockCompliance",
                "status": "FAILED",
                "statusMessage": error_message,
                "remediationMessage": "Must remove public access at a bucket level",
                "remediationLink": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                "severityLevel": "HIGH"
            }]
        }
