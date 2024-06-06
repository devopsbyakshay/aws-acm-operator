import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
from common_helper import log_function_entry_exit
from kubernetes import client, config

@log_function_entry_exit
def get_current_namespace():
    try:
        with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace') as f:
            namespace = f.read().strip()
            logger.debug(f"Current namespace read from file: {namespace}")
            return namespace
    except Exception as e:
        logger.error(f"Failed to read current namespace: {e}")
        return None
    
@log_function_entry_exit
def get_all_namespaces(current_namespace=None):
    try:
        # Load in-cluster configuration
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")

        # Create a Kubernetes API client
        v1 = client.CoreV1Api()

        if current_namespace:
            logger.info(f"Retrieving namespace information for the current namespace: {current_namespace}")
            namespace = v1.read_namespace(name=current_namespace)
            namespaces = [namespace]
        else:
            logger.info("Retrieving all namespaces")
            namespaces = v1.list_namespace().items

        # Extract namespace names and annotations
        namespace_info = []
        for namespace in namespaces:
            namespace_name = namespace.metadata.name
            annotations = namespace.metadata.annotations or {}
            namespace_info.append((namespace_name, annotations))
            logger.debug(f"Namespace: {namespace_name}, Annotations: {annotations}")

        return namespace_info

    except Exception as e:
        logger.error(f"Error retrieving namespaces: {e}")
        return []
    
@log_function_entry_exit
def get_all_services():
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")

        v1 = client.CoreV1Api()
        logger.info("Retrieving all services across all namespaces")
        services = v1.list_service_for_all_namespaces().items

        service_info = []
        for service in services:
            namespace_name = service.metadata.namespace
            service_name = service.metadata.name
            annotations = service.metadata.annotations or {}
            service_info.append((namespace_name, service_name, annotations))
            logger.debug(f"Namespace: {namespace_name}, Service: {service_name}, Annotations: {annotations}")

        return service_info

    except Exception as e:
        logger.error(f"Error retrieving services: {e}")
        return []

@log_function_entry_exit
def get_all_ingresses():
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")

        v1 = client.CoreV1Api()
        logger.info("Retrieving all ingress across all namespaces")
        services = v1.list_ingress_for_all_namespaces().items

        service_info = []
        for service in services:
            namespace_name = service.metadata.namespace
            service_name = service.metadata.name
            annotations = service.metadata.annotations or {}
            service_info.append((namespace_name, service_name, annotations))
            logger.debug(f"Namespace: {namespace_name}, Ingress: {service_name}, Annotations: {annotations}")

        return service_info

    except Exception as e:
        logger.error(f"Error retrieving ingresses: {e}")
        return []
    

@log_function_entry_exit
def get_acm_domain_from_services(service_list):
    domain_list = []
    if service_list:
        logger.info("Processing services for ACM domain annotations")
        for namespace, service, annotations in service_list:
            logger.info(f"Namespace: {namespace}, Service: {service}")
            logger.debug(f"Annotations: {annotations}")
            for key, value in annotations.items():
                if key == "aws.k8s.acm.manager/domain_name":
                    domain_list.append(value)
                logger.debug(f"  {key}: {value}")
    else:
        logger.error("No services found")
    return domain_list


@log_function_entry_exit
def get_acm_domain(namespace_list):
    domain_list = []
    if namespace_list:
        logger.info("Processing namespaces for ACM domain annotations")
        for namespace, annotations in namespace_list:
            logger.info(f"Namespace: {namespace}")
            logger.debug(f"Annotations: {annotations}")
            for key, value in annotations.items():
                if key == "aws.k8s.acm.manager/domain_name":
                    domain_list.append(value)
                logger.debug(f"  {key}: {value}")
    else:
        logger.error("No namespaces found")
    return domain_list

@log_function_entry_exit
def create_config_map(namespace, config_map_name, domain_name, cert_arn):
    config.load_incluster_config()
    domain_name = domain_name.replace("*", "star")
    v1 = client.CoreV1Api()
    try:
        # Try to create the ConfigMap
        body = client.V1ConfigMap(metadata=client.V1ObjectMeta(name=config_map_name), data={domain_name: cert_arn})
        v1.create_namespaced_config_map(namespace=namespace, body=body)
        logger.info(f"Created ConfigMap {config_map_name} in namespace {namespace}")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            # ConfigMap already exists, update it
            try:
                v1.patch_namespaced_config_map(name=config_map_name, namespace=namespace, body=body)
                logger.info(f"Updated ConfigMap {config_map_name} in namespace {namespace}")
            except Exception as update_e:
                logger.error(f"Failed to update ConfigMap {config_map_name} in namespace {namespace}: {update_e}")
        else:
            logger.error(f"Failed to create ConfigMap {config_map_name} in namespace {namespace}: {e}")
            raise


@log_function_entry_exit
def update_service_annotation(namespace, service_name, annotation_key, annotation_value):
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    try:
        service = v1.read_namespaced_service(name=service_name, namespace=namespace)
        if service.metadata.annotations is None:
            service.metadata.annotations = {}
        service.metadata.annotations[annotation_key] = annotation_value
        v1.patch_namespaced_service(name=service_name, namespace=namespace, body=service)
        logger.info(f"Updated service {service_name} in namespace {namespace} with annotation {annotation_key}: {annotation_value}")
    except Exception as e:
        logger.error(f"Failed to update service {service_name} in namespace {namespace} with annotation {annotation_key}: {annotation_value}, Error: {e}")


@log_function_entry_exit
def update_ingress_annotation(namespace, service_name, annotation_key, annotation_value):
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    try:
        service = v1.read_namespaced_ingress(name=service_name, namespace=namespace)
        if service.metadata.annotations is None:
            service.metadata.annotations = {}
        service.metadata.annotations[annotation_key] = annotation_value
        v1.patch_namespaced_ingress(name=service_name, namespace=namespace, body=service)
        logger.info(f"Updated Ingress {service_name} in namespace {namespace} with annotation {annotation_key}: {annotation_value}")
    except Exception as e:
        logger.error(f"Failed to update Ingress {service_name} in namespace {namespace} with annotation {annotation_key}: {annotation_value}, Error: {e}")


@log_function_entry_exit
def get_acm_domain_from_services(service_list, annotation_key_cert_domain):
    domain_list = []
    if service_list:
        logger.info("Processing services for ACM domain annotations")
        for namespace, service_name, annotations in service_list:
            logger.info(f"Namespace: {namespace}, Service: {service_name}")
            logger.debug(f"Annotations: {annotations}")
            for key, value in annotations.items():
                if key == annotation_key_cert_domain:
                    domain_list.append((namespace, service_name, value))
                logger.debug(f"  {key}: {value}")
    else:
        logger.error("No services found")
    return domain_list


@log_function_entry_exit
def get_config_map_data(namespace, config_map_name):
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    try:
        config_map = v1.read_namespaced_config_map(name=config_map_name, namespace=namespace)
        logger.info(f"Retrieved ConfigMap {config_map_name} from namespace {namespace}")
        if config_map.data != None:
            return config_map.data
        else:
            return {}
    except Exception as e:
        logger.error(f"Failed to retrieve ConfigMap {config_map_name} from namespace {namespace}: {e}")
        return {}

@log_function_entry_exit
def remove_from_config_map(namespace, config_map_name, domain_name):
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    try:
        config_map = v1.read_namespaced_config_map(name=config_map_name, namespace=namespace)
        logger.info(f"configmap data before deletion: {config_map.data}")
        if domain_name in config_map.data:
            del config_map.data[domain_name]
            logger.info(f"configmap data after deletion: {config_map.data}")
            v1.replace_namespaced_config_map(name=config_map_name, namespace=namespace, body=config_map)
            logger.info(f"Removed {domain_name} from ConfigMap {config_map_name} in namespace {namespace}")
    except client.exceptions.ApiException as e:
        logger.error(f"Failed to update ConfigMap {config_map_name} in namespace {namespace}: {e}")
        raise