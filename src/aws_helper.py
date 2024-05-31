import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
from common_helper import log_function_entry_exit
import time
import boto3


@log_function_entry_exit
def assume_role(role_arn):
    try:
        sts_client = boto3.client('sts')
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumeRoleSession"
        )
        credentials = assumed_role_object['Credentials']
        logger.info(f"Assumed role {role_arn}")
        
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    except Exception as e:
        logger.error(f"Failed to assume role {role_arn}: {e}")
        raise

@log_function_entry_exit
def get_acm_client():
    logger.info("Using default ACM client")
    return boto3.client('acm')

@log_function_entry_exit
def get_route53_client(is_cross_account, route53_account_assume_role_arn):
    if is_cross_account:
        session = assume_role(route53_account_assume_role_arn)
        logger.info("Using cross-account Route 53 client")
        return session.client('route53')
    else:
        logger.info("Using default Route 53 client")
        return boto3.client('route53')

@log_function_entry_exit
def find_cert(acm_client, domain_name):
    try:
        response = acm_client.list_certificates(CertificateStatuses=['PENDING_VALIDATION', 'ISSUED'])
        for cert in response['CertificateSummaryList']:
            if domain_name in cert['DomainName']:
                logger.info(f"Found certificate for domain {domain_name}: {cert['CertificateArn']}")
                return cert['CertificateArn']
        return None
    except Exception as e:
        logger.error(f"Failed to list certificates: {e}")
        return None

@log_function_entry_exit
def create_cert(acm_client, domain_name):
    try:
        response = acm_client.request_certificate(
            DomainName=domain_name,
            ValidationMethod='DNS'
        )
        cert_arn = response['CertificateArn']
        logger.info(f"Created certificate request for domain {domain_name}: {cert_arn}")
        return cert_arn
    except Exception as e:
        logger.error(f"Failed to create certificate for domain {domain_name}: {e}")
        return None
        

@log_function_entry_exit
def create_dns_validation(acm_client, route53_client, domain_name, cert_arn):
    try:
        response = acm_client.describe_certificate(CertificateArn=cert_arn)
        validation_options = response['Certificate']['DomainValidationOptions']
        
        hosted_zone_id = find_hosted_zone(route53_client, domain_name)
        
        logger.info(f"validation options: {validation_options}")
        changes = []
        for option in validation_options:
            if option['ValidationStatus'] == 'PENDING_VALIDATION':
                changes.append({
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': option['ResourceRecord']['Name'],
                        'Type': option['ResourceRecord']['Type'],
                        'TTL': 300,
                        'ResourceRecords': [{'Value': option['ResourceRecord']['Value']}]
                    }
                })
        
        response = route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Changes': changes
            }
        )
        logger.info(f"Created DNS validation records for domain {domain_name} in hosted zone {hosted_zone_id}")
    except Exception as e:
        logger.error(f"Failed to create DNS validation for domain {domain_name}: {e}")
        raise

@log_function_entry_exit
def find_hosted_zone(route53_client, domain_name):
    try:
        paginator = route53_client.get_paginator('list_hosted_zones')
        for page in paginator.paginate():
            for zone in page['HostedZones']:
                if domain_name.endswith(zone['Name'][:-1]):  # Removing trailing dot from zone name
                    logger.info(f"Found hosted zone {zone['Id']} for domain {domain_name}")
                    return zone['Id']
        raise Exception(f"Hosted zone not found for domain: {domain_name}")
    except Exception as e:
        logger.error(f"Failed to find hosted zone for domain {domain_name}: {e}")
        raise

@log_function_entry_exit
def wait_for_validation(acm_client, cert_arn, timeout=600, interval=10):
    elapsed = 0
    while elapsed < timeout:
        try:
            response = acm_client.describe_certificate(CertificateArn=cert_arn)
            if response['Certificate']['Status'] == 'ISSUED':
                logger.info(f"Certificate issued: {cert_arn}")
                return response['Certificate']['CertificateArn']
            time.sleep(interval)
            elapsed += interval
            logger.debug(f"Waiting for certificate {cert_arn} to be issued. Elapsed time: {elapsed} seconds")
        except Exception as e:
            logger.error(f"Error while waiting for certificate validation: {e}")
            raise
    raise Exception(f"Certificate validation timed out for {cert_arn}")

@log_function_entry_exit
def delete_dns_validation(acm_client, route53_client, domain_name, cert_arn):
    try:
        response = acm_client.describe_certificate(CertificateArn=cert_arn)
        validation_options = response['Certificate']['DomainValidationOptions']

        hosted_zone_id = find_hosted_zone(route53_client, domain_name)
        logger.info(f"validation options: {validation_options}")
        changes = []
        for option in validation_options:
            if option['ValidationMethod'] == 'DNS':
                changes.append({
                    'Action': 'DELETE',
                    'ResourceRecordSet': {
                        'Name': option['ResourceRecord']['Name'],
                        'Type': option['ResourceRecord']['Type'],
                        'TTL': 300,
                        'ResourceRecords': [{'Value': option['ResourceRecord']['Value']}]
                    }
                })

        response = route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Changes': changes
            }
        )
        logger.info(f"Deleted DNS validation records for domain {domain_name} in hosted zone {hosted_zone_id}")
    except Exception as e:
        logger.error(f"Failed to delete DNS validation for domain {domain_name}: {e}")
        raise


@log_function_entry_exit
def delete_cert(acm_client, cert_arn):
    try:
        acm_client.delete_certificate(CertificateArn=cert_arn)
        logger.info(f"Deleted ACM certificate: {cert_arn}")
    except Exception as e:
        logger.error(f"Failed to delete ACM certificate {cert_arn}: {e}")
