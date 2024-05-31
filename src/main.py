import logging
import os
import time
import datetime 
import pytz

from common_helper import log_function_entry_exit
from k8s_helper import create_config_map, get_acm_domain_from_services, get_all_services,get_config_map_data,get_current_namespace,update_service_annotation, remove_from_config_map
from aws_helper import create_cert, create_dns_validation, find_cert, get_acm_client, get_route53_client, wait_for_validation,delete_cert,delete_dns_validation
# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@log_function_entry_exit
def is_time_to_cleanup(time_zone='Asia/Kolkata', cleanup_hour=2):
    # Get the current UTC time
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    
    # Convert UTC time to the specified timezone
    tz = pytz.timezone(time_zone)
    now_tz = now_utc.astimezone(tz)
    
    # Check if the current time is the specified cleanup hour in the specified timezone
    return now_tz.hour == cleanup_hour

@log_function_entry_exit
def main():
    daily_cleanup_not_done = True
    while True:
        try:
            refresh_interval = int(os.getenv('REFRESH_INTERVAL', "60"))
            is_route53_cross_account = os.getenv('IS_ROUTE53_CROSS_ACCOUNT') == 'true'
            route53_account_assume_role_arn = os.getenv('ROUTE53_ACCOUNT_ASSUME_ROLE_ARN')
            config_map_name = os.getenv('CONFIG_MAP_NAME', 'acm-cert-config')
            current_namespace = get_current_namespace()
            annotation_key = os.getenv('CERT_ARN_ANNOTATION_KEY', 'aws.k8s.acm.manager/cert_arn')  # Annotation key for storing certificate ARN

            service_list = get_all_services()
            logger.info("Retrieved all services across all namespaces")

            acm_domain_list = get_acm_domain_from_services(service_list)
            logger.info(f"ACM domain list: {acm_domain_list}")

            # Process domains and update certificates
            for namespace, service_name, domain_name in acm_domain_list:
                acm_client = get_acm_client()
                cert_arn = find_cert(acm_client, domain_name)

                if cert_arn:
                    logger.info(f"Certificate already exists: {cert_arn}")
                else:
                    cert_arn = create_cert(acm_client, domain_name)
                    logger.info(f"Waiting for 10 seconds before making DNS records for cert validation")
                    time.sleep(10)
                    if cert_arn:
                        logger.info(f"Created certificate request: {cert_arn}")
                        route53_client = get_route53_client(is_route53_cross_account, route53_account_assume_role_arn)
                        create_dns_validation(acm_client, route53_client, domain_name, cert_arn)
                        cert_arn = wait_for_validation(acm_client, cert_arn)
                        logger.info(f"Certificate validated: {cert_arn}")
                    else:
                        logger.error(f"Failed to create certificate for domain {domain_name}")
                logger.info(f"Updating configmap {config_map_name} at namespace {current_namespace} with cert arn: {cert_arn}")
                create_config_map(current_namespace, config_map_name, domain_name, cert_arn)

                logger.info(f"Updating service {service_name} in namespace {namespace} with annotation {annotation_key}: {cert_arn}")
                update_service_annotation(namespace, service_name, annotation_key, cert_arn)

            # Cleanup process
            if is_time_to_cleanup():
                if daily_cleanup_not_done:
                    config_map_data = get_config_map_data(current_namespace, config_map_name)
                    service_certs = {annotation_value for namespace, service_name, annotation_value in acm_domain_list}
                    logger.info(f"service certs: {service_certs}")
                    logger.info(f"configmap data: {config_map_data}")
                    for domain_name, cert_arn in config_map_data.items():
                        logger.info(f"checking for cert arn {cert_arn} in service_certs")
                        if domain_name not in service_certs:
                            logger.info(f"Cleaning up certificate {cert_arn} for domain {domain_name}")
                            acm_client = get_acm_client()
                            route53_client = get_route53_client(is_route53_cross_account, route53_account_assume_role_arn)
                            delete_dns_validation(acm_client,route53_client, domain_name, cert_arn)
                            
                            delete_cert(acm_client, cert_arn)
                            logger.info(f"Removed certificate {cert_arn} and DNS validation for domain {domain_name} from ConfigMap {config_map_name}")
                            remove_from_config_map(current_namespace, config_map_name, domain_name)
                    daily_cleanup_not_done = False
            else:
                daily_cleanup_not_done = True
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        logger.info(f"Waiting for {refresh_interval} seconds before the next iteration")
        time.sleep(refresh_interval)

if __name__ == "__main__":
    logger.info("started acm operator")
    main()