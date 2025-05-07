import boto3
import csv
from datetime import datetime, timezone
from dateutil import parser as date_parser  # Requires: pip install python-dateutil

# === Configuration ===
CUTOFF = datetime(2025, 2, 1, tzinfo=timezone.utc)
REGIONS = ['us-east-1', 'us-east-2']
TAG_KEY = 'map-migrated'
TAG_VALUE = 'migQHF59B16KD'

# === Get AWS Account ID ===
sts = boto3.client('sts')
account_id = sts.get_caller_identity()['Account']

# === CSV Setup ===
csv_filename = f"tagging_report_{account_id}.csv"
csvfile = open(csv_filename, "w", newline="")
csv_writer = csv.writer(csvfile)
csv_writer.writerow(["Region", "Resource ID", "Service", "Tag Status", "Tag Value", "Creation Date", "Message"])

# === EC2 Tagging ===
def process_ec2_instances():
    for region in REGIONS:
        print(f"Scanning EC2 instances in region: {region}")
        ec2 = boto3.client('ec2', region_name=region)
        reservations = ec2.describe_instances().get('Reservations', [])

        for reservation in reservations:
            for instance in reservation.get('Instances', []):
                instance_id = instance['InstanceId']
                launch_time = instance['LaunchTime']
                tags = instance.get('Tags', [])

                tag_value = next((tag['Value'] for tag in tags if tag['Key'] == TAG_KEY), None)

                if tag_value == TAG_VALUE:
                    message = f"Skipping EC2: {instance_id} (already tagged with correct value)"
                    print(message)
                    csv_writer.writerow([region, instance_id, "EC2", "Already Tagged", tag_value, launch_time, message])
                    continue
                elif tag_value:
                    message = f"EC2 {instance_id} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, instance_id, "EC2", "Conflicting Tag", tag_value, launch_time, message])
                    continue

                if launch_time >= CUTOFF:
                    try:
                        ec2.create_tags(Resources=[instance_id], Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                        message = f"Successfully tagged EC2: {instance_id}"
                        print(message)
                        csv_writer.writerow([region, instance_id, "EC2", "Tagged", TAG_VALUE, launch_time, message])
                    except Exception as e:
                        message = f"Failed to tag EC2: {instance_id}. Error: {str(e)}"
                        print(message)
                        csv_writer.writerow([region, instance_id, "EC2", "Failed", "", launch_time, message])
                else:
                    message = f"Skipping EC2: {instance_id} (too old: {launch_time})"
                    print(message)
                    csv_writer.writerow([region, instance_id, "EC2", "Skipped - Too Old", "", launch_time, message])

# === Lambda Tagging ===
def process_lambda_functions():
    for region in REGIONS:
        print(f"Scanning Lambda functions in region: {region}")
        lambda_client = boto3.client('lambda', region_name=region)
        paginator = lambda_client.get_paginator('list_functions')

        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function['FunctionName']
                function_arn = function['FunctionArn']

                try:
                    config = lambda_client.get_function_configuration(FunctionName=function_name)
                    last_modified = date_parser.parse(config['LastModified']).astimezone(timezone.utc)

                    tags = lambda_client.list_tags(Resource=function_arn).get('Tags', {})
                    tag_value = tags.get(TAG_KEY)

                    if tag_value == TAG_VALUE:
                        message = f"Skipping Lambda: {function_name} (already tagged with correct value)"
                        print(message)
                        csv_writer.writerow([region, function_name, "Lambda", "Already Tagged", tag_value, last_modified, message])
                        continue
                    elif tag_value:
                        message = f"Lambda {function_name} has conflicting tag value: {tag_value}"
                        print(message)
                        csv_writer.writerow([region, function_name, "Lambda", "Conflicting Tag", tag_value, last_modified, message])
                        continue

                    if last_modified >= CUTOFF:
                        lambda_client.tag_resource(Resource=function_arn, Tags={TAG_KEY: TAG_VALUE})
                        message = f"Successfully tagged Lambda: {function_name}"
                        print(message)
                        csv_writer.writerow([region, function_name, "Lambda", "Tagged", TAG_VALUE, last_modified, message])
                    else:
                        message = f"Skipping Lambda: {function_name} (too old: {last_modified})"
                        print(message)
                        csv_writer.writerow([region, function_name, "Lambda", "Skipped - Too Old", "", last_modified, message])

                except Exception as e:
                    message = f"Failed to process Lambda: {function_name}. Error: {str(e)}"
                    print(message)
                    csv_writer.writerow([region, function_name, "Lambda", "Failed", "", "", message])

# === RDS Tagging ===
def process_rds_instances():
    for region in REGIONS:
        print(f"Scanning RDS instances in region: {region}")
        rds = boto3.client('rds', region_name=region)
        try:
            dbs = rds.describe_db_instances()['DBInstances']
        except Exception as e:
            print(f"Failed to retrieve RDS instances in {region}: {e}")
            continue

        for db in dbs:
            db_id = db['DBInstanceIdentifier']
            db_arn = db['DBInstanceArn']
            creation_time = db['InstanceCreateTime']

            try:
                tags = rds.list_tags_for_resource(ResourceName=db_arn).get('TagList', [])
                tag_value = next((tag['Value'] for tag in tags if tag['Key'] == TAG_KEY), None)

                if tag_value == TAG_VALUE:
                    message = f"Skipping RDS: {db_id} (already tagged with correct value)"
                    print(message)
                    csv_writer.writerow([region, db_id, "RDS", "Already Tagged", tag_value, creation_time, message])
                    continue
                elif tag_value:
                    message = f"RDS {db_id} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, db_id, "RDS", "Conflicting Tag", tag_value, creation_time, message])
                    continue

                if creation_time >= CUTOFF:
                    rds.add_tags_to_resource(ResourceName=db_arn, Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged RDS: {db_id}"
                    print(message)
                    csv_writer.writerow([region, db_id, "RDS", "Tagged", TAG_VALUE, creation_time, message])
                else:
                    message = f"Skipping RDS: {db_id} (too old: {creation_time})"
                    print(message)
                    csv_writer.writerow([region, db_id, "RDS", "Skipped - Too Old", "", creation_time, message])

            except Exception as e:
                message = f"Failed to process RDS: {db_id}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, db_id, "RDS", "Failed", "", creation_time, message])

# === EBS Tagging ===
def process_ebs_volumes():
    for region in REGIONS:
        print(f"Scanning EBS volumes in region: {region}")
        ec2 = boto3.client('ec2', region_name=region)
        try:
            volumes = ec2.describe_volumes()['Volumes']
        except Exception as e:
            print(f"Failed to retrieve EBS volumes in {region}: {e}")
            continue

        for volume in volumes:
            volume_id = volume['VolumeId']
            create_time = volume['CreateTime']
            tags = volume.get('Tags', [])
            tag_value = next((tag['Value'] for tag in tags if tag['Key'] == TAG_KEY), None)

            if tag_value == TAG_VALUE:
                message = f"Skipping EBS: {volume_id} (already tagged with correct value)"
                print(message)
                csv_writer.writerow([region, volume_id, "EBS", "Already Tagged", tag_value, create_time, message])
                continue
            elif tag_value:
                message = f"EBS {volume_id} has conflicting tag value: {tag_value}"
                print(message)
                csv_writer.writerow([region, volume_id, "EBS", "Conflicting Tag", tag_value, create_time, message])
                continue

            if create_time >= CUTOFF:
                try:
                    ec2.create_tags(Resources=[volume_id], Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged EBS: {volume_id}"
                    print(message)
                    csv_writer.writerow([region, volume_id, "EBS", "Tagged", TAG_VALUE, create_time, message])
                except Exception as e:
                    message = f"Failed to tag EBS: {volume_id}. Error: {str(e)}"
                    print(message)
                    csv_writer.writerow([region, volume_id, "EBS", "Failed", "", create_time, message])
            else:
                message = f"Skipping EBS: {volume_id} (too old: {create_time})"
                print(message)
                csv_writer.writerow([region, volume_id, "EBS", "Skipped - Too Old", "", create_time, message])

def process_s3_buckets():
    for region in REGIONS:
        print(f"Scanning S3 buckets in region: {region}")
        s3 = boto3.client('s3', region_name=region)

        try:
            buckets = s3.list_buckets().get('Buckets', [])
        except Exception as e:
            print(f"Failed to retrieve S3 buckets in {region}: {e}")
            continue

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                # Get bucket creation date
                creation_date = bucket.get('CreationDate', datetime.min.replace(tzinfo=timezone.utc))

                # Get bucket tags
                try:
                    tag_set = s3.get_bucket_tagging(Bucket=bucket_name).get('TagSet', [])
                    tags = {tag['Key']: tag['Value'] for tag in tag_set}
                except s3.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchTagSet':
                        tags = {}
                    else:
                        raise

                tag_value = tags.get(TAG_KEY)

                if tag_value == TAG_VALUE:
                    message = f"Skipping S3 bucket: {bucket_name} (already tagged with correct value)"
                    print(message)
                    csv_writer.writerow([region, bucket_name, "S3", "Already Tagged", tag_value, creation_date, message])
                    continue
                elif tag_value:
                    message = f"S3 bucket {bucket_name} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, bucket_name, "S3", "Conflicting Tag", tag_value, creation_date, message])
                    continue

                if creation_date >= CUTOFF:
                    # Merge with existing tags
                    tags[TAG_KEY] = TAG_VALUE
                    tag_set = [{'Key': k, 'Value': v} for k, v in tags.items()]

                    s3.put_bucket_tagging(
                        Bucket=bucket_name,
                        Tagging={'TagSet': tag_set}
                    )
                    message = f"Successfully tagged S3 bucket: {bucket_name}"
                    print(message)
                    csv_writer.writerow([region, bucket_name, "S3", "Tagged", TAG_VALUE, creation_date, message])
                else:
                    message = f"Skipping S3 bucket: {bucket_name} (too old: {creation_date})"
                    print(message)
                    csv_writer.writerow([region, bucket_name, "S3", "Skipped - Too Old", "", creation_date, message])

            except Exception as e:
                message = f"Failed to process S3 bucket: {bucket_name}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, bucket_name, "S3", "Failed", "", "", message])


# === ECS Tagging ===
def process_ecs_clusters():
    for region in REGIONS:
        print(f"Scanning ECS clusters in region: {region}")
        ecs = boto3.client('ecs', region_name=region)

        try:
            # List all ECS clusters
            cluster_arns = ecs.list_clusters().get('clusterArns', [])
        except Exception as e:
            print(f"Failed to retrieve ECS clusters in {region}: {e}")
            continue

        for cluster_arn in cluster_arns:
            try:
                # Describe the cluster to get its tags
                cluster_details = ecs.describe_clusters(clusters=[cluster_arn], include=['TAGS']).get('clusters', [])
                if not cluster_details:
                    continue

                cluster = cluster_details[0]
                cluster_name = cluster['clusterName']
                tags = {tag['key']: tag['value'] for tag in cluster.get('tags', [])}
                tag_value = tags.get(TAG_KEY)

                # Check if the cluster has a "CreatedOn" tag
                created_on = tags.get('CreatedOn')
                if created_on:
                    created_on_date = date_parser.parse(created_on).astimezone(timezone.utc)
                    if created_on_date < CUTOFF:
                        message = f"Skipping ECS cluster: {cluster_name} (too old: {created_on_date})"
                        print(message)
                        csv_writer.writerow([region, cluster_arn, "ECS", "Skipped - Too Old", "", created_on_date, message])
                        continue

                # Check if the cluster is already tagged
                if tag_value == TAG_VALUE:
                    message = f"Skipping ECS cluster: {cluster_name} (already tagged with correct value)"
                    print(message)
                    csv_writer.writerow([region, cluster_arn, "ECS", "Already Tagged", tag_value, "", message])
                    continue
                elif tag_value:
                    message = f"ECS cluster {cluster_name} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, cluster_arn, "ECS", "Conflicting Tag", tag_value, "", message])
                    continue

                # Tag the cluster
                ecs.tag_resource(
                    resourceArn=cluster_arn,
                    tags=[{'key': TAG_KEY, 'value': TAG_VALUE}]
                )
                message = f"Successfully tagged ECS cluster: {cluster_name}"
                print(message)
                csv_writer.writerow([region, cluster_arn, "ECS", "Tagged", TAG_VALUE, "", message])

            except Exception as e:
                message = f"Failed to process ECS cluster: {cluster_arn}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, cluster_arn, "ECS", "Failed", "", "", message])

# === EC2 Snapshots Tagging ===
def process_snapshots():
    for region in REGIONS:
        print(f"Scanning Snapshots in region: {region}")
        ec2 = boto3.client('ec2', region_name=region)
        try:
            snapshots = ec2.describe_snapshots(OwnerIds=['self']).get('Snapshots', [])
        except Exception as e:
            print(f"Failed to retrieve Snapshots in {region}: {e}")
            continue

        for snapshot in snapshots:
            snapshot_id = snapshot['SnapshotId']
            start_time = snapshot['StartTime']
            tags = snapshot.get('Tags', [])
            tag_value = next((tag['Value'] for tag in tags if tag['Key'] == TAG_KEY), None)

            if tag_value == TAG_VALUE:
                message = f"Skipping Snapshot: {snapshot_id} (already tagged with correct value)"
                print(message)
                csv_writer.writerow([region, snapshot_id, "Snapshot", "Already Tagged", tag_value, start_time, message])
                continue
            elif tag_value:
                message = f"Snapshot {snapshot_id} has conflicting tag value: {tag_value}"
                print(message)
                csv_writer.writerow([region, snapshot_id, "Snapshot", "Conflicting Tag", tag_value, start_time, message])
                continue

            if start_time >= CUTOFF:
                try:
                    ec2.create_tags(Resources=[snapshot_id], Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged Snapshot: {snapshot_id}"
                    print(message)
                    csv_writer.writerow([region, snapshot_id, "Snapshot", "Tagged", TAG_VALUE, start_time, message])
                except Exception as e:
                    message = f"Failed to tag Snapshot: {snapshot_id}. Error: {str(e)}"
                    print(message)
                    csv_writer.writerow([region, snapshot_id, "Snapshot", "Failed", "", start_time, message])
            else:
                message = f"Skipping Snapshot: {snapshot_id} (too old: {start_time})"
                print(message)
                csv_writer.writerow([region, snapshot_id, "Snapshot", "Skipped - Too Old", "", start_time, message])

# === AMI Images Tagging ===
def process_ami_images():
    for region in REGIONS:
        print(f"Scanning AMI Images in region: {region}")
        ec2 = boto3.client('ec2', region_name=region)
        try:
            images = ec2.describe_images(Owners=['self']).get('Images', [])
        except Exception as e:
            print(f"Failed to retrieve AMI Images in {region}: {e}")
            continue

        for image in images:
            image_id = image['ImageId']
            creation_date = date_parser.parse(image['CreationDate']).astimezone(timezone.utc)
            tags = image.get('Tags', [])
            tag_value = next((tag['Value'] for tag in tags if tag['Key'] == TAG_KEY), None)

            if tag_value == TAG_VALUE:
                message = f"Skipping AMI Image: {image_id} (already tagged with correct value)"
                print(message)
                csv_writer.writerow([region, image_id, "AMI", "Already Tagged", tag_value, creation_date, message])
                continue
            elif tag_value:
                message = f"AMI Image {image_id} has conflicting tag value: {tag_value}"
                print(message)
                csv_writer.writerow([region, image_id, "AMI", "Conflicting Tag", tag_value, creation_date, message])
                continue

            if creation_date >= CUTOFF:
                try:
                    ec2.create_tags(Resources=[image_id], Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged AMI Image: {image_id}"
                    print(message)
                    csv_writer.writerow([region, image_id, "AMI", "Tagged", TAG_VALUE, creation_date, message])
                except Exception as e:
                    message = f"Failed to tag AMI Image: {image_id}. Error: {str(e)}"
                    print(message)
                    csv_writer.writerow([region, image_id, "AMI", "Failed", "", creation_date, message])
            else:
                message = f"Skipping AMI Image: {image_id} (too old: {creation_date})"
                print(message)
                csv_writer.writerow([region, image_id, "AMI", "Skipped - Too Old", "", creation_date, message])
                
# === Elastic Load Balancer Tagging ===
def process_elbs():
    for region in REGIONS:
        print(f"Scanning ELBs in region: {region}")
        elb = boto3.client('elbv2', region_name=region)
        try:
            elbs = elb.describe_load_balancers()['LoadBalancers']
        except Exception as e:
            print(f"Failed to retrieve ELBs in {region}: {e}")
            continue
        for lb in elbs:
            lb_arn = lb['LoadBalancerArn']
            lb_name = lb['LoadBalancerName']
            created_time = lb['CreatedTime']
            try:
                tags = elb.describe_tags(ResourceArns=[lb_arn])['TagDescriptions'][0].get('Tags', [])
                tag_value = next((tag['Value'] for tag in tags if tag['Key'] == TAG_KEY), None)
                if tag_value == TAG_VALUE:
                    message = f"Skipping ELB: {lb_name} (already tagged)"
                    print(message)
                    csv_writer.writerow([region, lb_name, "ELB", "Already Tagged", tag_value, created_time, message])
                    continue
                elif tag_value:
                    message = f"ELB {lb_name} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, lb_name, "ELB", "Conflicting Tag", tag_value, created_time, message])
                    continue
                if created_time >= CUTOFF:
                    elb.add_tags(ResourceArns=[lb_arn], Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged ELB: {lb_name}"
                    print(message)
                    csv_writer.writerow([region, lb_name, "ELB", "Tagged", TAG_VALUE, created_time, message])
                else:
                    message = f"Skipping ELB: {lb_name} (too old: {created_time})"
                    print(message)
                    csv_writer.writerow([region, lb_name, "ELB", "Skipped - Too Old", "", created_time, message])
            except Exception as e:
                message = f"Failed to process ELB: {lb_name}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, lb_name, "ELB", "Failed", "", created_time, message])

# === Secrets Manager Tagging ===
def process_secrets():
    for region in REGIONS:
        print(f"Scanning Secrets Manager secrets in region: {region}")
        sm = boto3.client('secretsmanager', region_name=region)
        try:
            secrets = sm.list_secrets()['SecretList']
        except Exception as e:
            print(f"Failed to retrieve secrets in {region}: {e}")
            continue
        for secret in secrets:
            secret_arn = secret['ARN']
            secret_name = secret['Name']
            created_date = secret.get('CreatedDate', datetime.min.replace(tzinfo=timezone.utc))
            try:
                tags = {t['Key']: t['Value'] for t in secret.get('Tags', [])}
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping Secret: {secret_name} (already tagged)"
                    print(message)
                    csv_writer.writerow([region, secret_name, "SecretsManager", "Already Tagged", tag_value, created_date, message])
                    continue
                elif tag_value:
                    message = f"Secret {secret_name} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, secret_name, "SecretsManager", "Conflicting Tag", tag_value, created_date, message])
                    continue
                if created_date >= CUTOFF:
                    sm.tag_resource(SecretId=secret_arn, Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged Secret: {secret_name}"
                    print(message)
                    csv_writer.writerow([region, secret_name, "SecretsManager", "Tagged", TAG_VALUE, created_date, message])
                else:
                    message = f"Skipping Secret: {secret_name} (too old: {created_date})"
                    print(message)
                    csv_writer.writerow([region, secret_name, "SecretsManager", "Skipped - Too Old", "", created_date, message])
            except Exception as e:
                message = f"Failed to process Secret: {secret_name}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, secret_name, "SecretsManager", "Failed", "", created_date, message])

# === SQS Tagging ===
def process_sqs_queues():
    for region in REGIONS:
        print(f"Scanning SQS queues in region: {region}")
        sqs = boto3.client('sqs', region_name=region)
        try:
            queue_urls = sqs.list_queues().get('QueueUrls', [])
        except Exception as e:
            print(f"Failed to retrieve SQS queues in {region}: {e}")
            continue
        for url in queue_urls:
            try:
                attributes = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=['CreatedTimestamp'])['Attributes']
                created_time = datetime.fromtimestamp(int(attributes['CreatedTimestamp']), tz=timezone.utc)
                tags = sqs.list_queue_tags(QueueUrl=url).get('Tags', {})
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping SQS: {url} (already tagged)"
                    print(message)
                    csv_writer.writerow([region, url, "SQS", "Already Tagged", tag_value, created_time, message])
                    continue
                elif tag_value:
                    message = f"SQS {url} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, url, "SQS", "Conflicting Tag", tag_value, created_time, message])
                    continue
                if created_time >= CUTOFF:
                    sqs.tag_queue(QueueUrl=url, Tags={TAG_KEY: TAG_VALUE})
                    message = f"Successfully tagged SQS: {url}"
                    print(message)
                    csv_writer.writerow([region, url, "SQS", "Tagged", TAG_VALUE, created_time, message])
                else:
                    message = f"Skipping SQS: {url} (too old: {created_time})"
                    print(message)
                    csv_writer.writerow([region, url, "SQS", "Skipped - Too Old", "", created_time, message])
            except Exception as e:
                message = f"Failed to process SQS: {url}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, url, "SQS", "Failed", "", "", message])
def process_kms_keys():
    for region in REGIONS:
        print(f"Scanning KMS Keys in region: {region}")
        kms = boto3.client('kms', region_name=region)
        try:
            keys = kms.list_keys()['Keys']
        except Exception as e:
            print(f"Failed to retrieve KMS keys in {region}: {e}")
            continue
        for key in keys:
            key_id = key['KeyId']
            try:
                key_metadata = kms.describe_key(KeyId=key_id)['KeyMetadata']
                creation_date = key_metadata['CreationDate']
                tags = {tag['TagKey']: tag['TagValue'] for tag in kms.list_resource_tags(KeyId=key_id)['Tags']}
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping KMS Key: {key_id} (already tagged)"
                    print(message)
                    csv_writer.writerow([region, key_id, "KMS", "Already Tagged", tag_value, creation_date, message])
                    continue
                elif tag_value:
                    message = f"KMS Key {key_id} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, key_id, "KMS", "Conflicting Tag", tag_value, creation_date, message])
                    continue
                if creation_date >= CUTOFF:
                    kms.tag_resource(KeyId=key_id, Tags=[{'TagKey': TAG_KEY, 'TagValue': TAG_VALUE}])
                    message = f"Successfully tagged KMS Key: {key_id}"
                    print(message)
                    csv_writer.writerow([region, key_id, "KMS", "Tagged", TAG_VALUE, creation_date, message])
                else:
                    message = f"Skipping KMS Key: {key_id} (too old: {creation_date})"
                    print(message)
                    csv_writer.writerow([region, key_id, "KMS", "Skipped - Too Old", "", creation_date, message])
            except Exception as e:
                message = f"Failed to process KMS Key: {key_id}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, key_id, "KMS", "Failed", "", "", message])
def process_api_gateways():
    for region in REGIONS:
        print(f"Scanning API Gateways in region: {region}")
        apigw = boto3.client('apigateway', region_name=region)
        try:
            apis = apigw.get_rest_apis()['items']
        except Exception as e:
            print(f"Failed to retrieve API Gateways in {region}: {e}")
            continue
        for api in apis:
            api_id = api['id']
            api_name = api['name']
            created_date = api.get('createdDate', datetime.min.replace(tzinfo=timezone.utc))
            arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}"
            try:
                tags = apigw.get_tags(resourceArn=arn)
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping API Gateway: {api_name} (already tagged)"
                    print(message)
                    csv_writer.writerow([region, api_id, "APIGateway", "Already Tagged", tag_value, created_date, message])
                    continue
                elif tag_value:
                    message = f"API Gateway {api_name} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, api_id, "APIGateway", "Conflicting Tag", tag_value, created_date, message])
                    continue
                if created_date >= CUTOFF:
                    apigw.tag_resource(resourceArn=arn, tags={TAG_KEY: TAG_VALUE})
                    message = f"Successfully tagged API Gateway: {api_name}"
                    print(message)
                    csv_writer.writerow([region, api_id, "APIGateway", "Tagged", TAG_VALUE, created_date, message])
                else:
                    message = f"Skipping API Gateway: {api_name} (too old: {created_date})"
                    print(message)
                    csv_writer.writerow([region, api_id, "APIGateway", "Skipped - Too Old", "", created_date, message])
            except Exception as e:
                message = f"Failed to process API Gateway: {api_name}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, api_id, "APIGateway", "Failed", "", created_date, message])
def process_ecr_repositories():
    for region in REGIONS:
        print(f"Scanning ECR Repositories in region: {region}")
        ecr = boto3.client('ecr', region_name=region)
        try:
            repos = ecr.describe_repositories()['repositories']
        except Exception as e:
            print(f"Failed to retrieve ECR repositories in {region}: {e}")
            continue
        for repo in repos:
            repo_name = repo['repositoryName']
            arn = repo['repositoryArn']
            created = repo['createdAt']
            try:
                tags = {tag['Key']: tag['Value'] for tag in ecr.list_tags_for_resource(resourceArn=arn)['tags']}
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping ECR: {repo_name} (already tagged)"
                    print(message)
                    csv_writer.writerow([region, repo_name, "ECR", "Already Tagged", tag_value, created, message])
                    continue
                elif tag_value:
                    message = f"ECR {repo_name} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, repo_name, "ECR", "Conflicting Tag", tag_value, created, message])
                    continue
                if created >= CUTOFF:
                    ecr.tag_resource(resourceArn=arn, tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged ECR: {repo_name}"
                    print(message)
                    csv_writer.writerow([region, repo_name, "ECR", "Tagged", TAG_VALUE, created, message])
                else:
                    message = f"Skipping ECR: {repo_name} (too old: {created})"
                    print(message)
                    csv_writer.writerow([region, repo_name, "ECR", "Skipped - Too Old", "", created, message])
            except Exception as e:
                message = f"Failed to process ECR: {repo_name}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, repo_name, "ECR", "Failed", "", "", message])
def process_vpcs():
    for region in REGIONS:
        print(f"Scanning VPCs in region: {region}")
        ec2 = boto3.client('ec2', region_name=region)
        try:
            vpcs = ec2.describe_vpcs()['Vpcs']
        except Exception as e:
            print(f"Failed to retrieve VPCs in {region}: {e}")
            continue
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            tags = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
            tag_value = tags.get(TAG_KEY)
            if tag_value == TAG_VALUE:
                message = f"Skipping VPC: {vpc_id} (already tagged)"
                print(message)
                csv_writer.writerow([region, vpc_id, "VPC", "Already Tagged", tag_value, "", message])
                continue
            elif tag_value:
                message = f"VPC {vpc_id} has conflicting tag value: {tag_value}"
                print(message)
                csv_writer.writerow([region, vpc_id, "VPC", "Conflicting Tag", tag_value, "", message])
                continue
            try:
                ec2.create_tags(Resources=[vpc_id], Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                message = f"Successfully tagged VPC: {vpc_id}"
                print(message)
                csv_writer.writerow([region, vpc_id, "VPC", "Tagged", TAG_VALUE, "", message])
            except Exception as e:
                message = f"Failed to tag VPC: {vpc_id}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, vpc_id, "VPC", "Failed", "", "", message])
def process_cloudwatch_log_groups():
    for region in REGIONS:
        print(f"Scanning CloudWatch Log Groups in region: {region}")
        logs = boto3.client('logs', region_name=region)
        try:
            paginator = logs.get_paginator('describe_log_groups')
            for page in paginator.paginate():
                for group in page.get('logGroups', []):
                    log_group_name = group['logGroupName']
                    tags = logs.list_tags_log_group(logGroupName=log_group_name).get('tags', {})
                    tag_value = tags.get(TAG_KEY)
                    if tag_value == TAG_VALUE:
                        message = f"Skipping Log Group: {log_group_name} (already tagged)"
                        print(message)
                        csv_writer.writerow([region, log_group_name, "CloudWatchLogs", "Already Tagged", tag_value, "", message])
                        continue
                    elif tag_value:
                        message = f"Log Group {log_group_name} has conflicting tag value: {tag_value}"
                        print(message)
                        csv_writer.writerow([region, log_group_name, "CloudWatchLogs", "Conflicting Tag", tag_value, "", message])
                        continue
                    logs.tag_log_group(logGroupName=log_group_name, tags={TAG_KEY: TAG_VALUE})
                    message = f"Successfully tagged Log Group: {log_group_name}"
                    print(message)
                    csv_writer.writerow([region, log_group_name, "CloudWatchLogs", "Tagged", TAG_VALUE, "", message])
        except Exception as e:
            print(f"Failed to retrieve Log Groups in {region}: {e}")
def process_cloudwatch_alarms():
    for region in REGIONS:
        print(f"Scanning CloudWatch Alarms in region: {region}")
        cloudwatch = boto3.client('cloudwatch', region_name=region)
        try:
            alarms = cloudwatch.describe_alarms()['MetricAlarms']
        except Exception as e:
            print(f"Failed to retrieve Alarms in {region}: {e}")
            continue
        for alarm in alarms:
            alarm_name = alarm['AlarmName']
            arn = alarm['AlarmArn']
            try:
                tags = cloudwatch.list_tags_for_resource(ResourceARN=arn).get('Tags', [])
                tags_dict = {t['Key']: t['Value'] for t in tags}
                tag_value = tags_dict.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping Alarm: {alarm_name} (already tagged)"
                    print(message)
                    csv_writer.writerow([region, alarm_name, "CloudWatchAlarm", "Already Tagged", tag_value, "", message])
                    continue
                elif tag_value:
                    message = f"Alarm {alarm_name} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, alarm_name, "CloudWatchAlarm", "Conflicting Tag", tag_value, "", message])
                    continue
                cloudwatch.tag_resource(ResourceARN=arn, Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                message = f"Successfully tagged Alarm: {alarm_name}"
                print(message)
                csv_writer.writerow([region, alarm_name, "CloudWatchAlarm", "Tagged", TAG_VALUE, "", message])
            except Exception as e:
                message = f"Failed to tag Alarm: {alarm_name}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, alarm_name, "CloudWatchAlarm", "Failed", "", "", message])
def process_config_rules():
    for region in REGIONS:
        print(f"Scanning Config Rules in region: {region}")
        config = boto3.client('config', region_name=region)
        try:
            rules = config.describe_config_rules().get('ConfigRules', [])
        except Exception as e:
            print(f"Failed to retrieve Config Rules in {region}: {e}")
            continue
        for rule in rules:
            rule_name = rule['ConfigRuleName']
            arn = rule['ConfigRuleArn']
            try:
                tags = config.list_tags_for_resource(ResourceArn=arn).get('Tags', [])
                tag_value = next((t['Value'] for t in tags if t['Key'] == TAG_KEY), None)
                if tag_value == TAG_VALUE:
                    message = f"Skipping Config Rule: {rule_name} (already tagged)"
                    print(message)
                    csv_writer.writerow([region, rule_name, "ConfigRule", "Already Tagged", tag_value, "", message])
                    continue
                elif tag_value:
                    message = f"Config Rule {rule_name} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, rule_name, "ConfigRule", "Conflicting Tag", tag_value, "", message])
                    continue
                config.tag_resource(ResourceArn=arn, Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                message = f"Successfully tagged Config Rule: {rule_name}"
                print(message)
                csv_writer.writerow([region, rule_name, "ConfigRule", "Tagged", TAG_VALUE, "", message])
            except Exception as e:
                message = f"Failed to tag Config Rule: {rule_name}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, rule_name, "ConfigRule", "Failed", "", "", message])
def process_nat_gateways():
    for region in REGIONS:
        print(f"Scanning NAT Gateways in region: {region}")
        ec2 = boto3.client('ec2', region_name=region)
        try:
            nats = ec2.describe_nat_gateways()['NatGateways']
        except Exception as e:
            print(f"Failed to retrieve NAT Gateways in {region}: {e}")
            continue
        for nat in nats:
            nat_id = nat['NatGatewayId']
            create_time = nat['CreateTime']
            tags = {tag['Key']: tag['Value'] for tag in nat.get('Tags', [])}
            tag_value = tags.get(TAG_KEY)
            if tag_value == TAG_VALUE:
                message = f"Skipping NAT Gateway: {nat_id} (already tagged)"
            elif tag_value:
                message = f"NAT Gateway {nat_id} has conflicting tag value: {tag_value}"
            elif create_time >= CUTOFF:
                try:
                    ec2.create_tags(Resources=[nat_id], Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged NAT Gateway: {nat_id}"
                except Exception as e:
                    message = f"Failed to tag NAT Gateway: {nat_id}. Error: {str(e)}"
            else:
                message = f"Skipping NAT Gateway: {nat_id} (too old: {create_time})"
            print(message)
            csv_writer.writerow([region, nat_id, "NATGateway", "", tag_value or TAG_VALUE, create_time, message])
def process_internet_gateways():
    for region in REGIONS:
        print(f"Scanning Internet Gateways in region: {region}")
        ec2 = boto3.client('ec2', region_name=region)
        try:
            igws = ec2.describe_internet_gateways()['InternetGateways']
        except Exception as e:
            print(f"Failed to retrieve Internet Gateways in {region}: {e}")
            continue
        for igw in igws:
            igw_id = igw['InternetGatewayId']
            tags = {tag['Key']: tag['Value'] for tag in igw.get('Tags', [])}
            tag_value = tags.get(TAG_KEY)
            if tag_value == TAG_VALUE:
                message = f"Skipping Internet Gateway: {igw_id} (already tagged)"
            elif tag_value:
                message = f"Internet Gateway {igw_id} has conflicting tag value: {tag_value}"
            else:
                try:
                    ec2.create_tags(Resources=[igw_id], Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged Internet Gateway: {igw_id}"
                except Exception as e:
                    message = f"Failed to tag Internet Gateway: {igw_id}. Error: {str(e)}"
            print(message)
            csv_writer.writerow([region, igw_id, "InternetGateway", "", tag_value or TAG_VALUE, "", message])
def process_vpc_peerings():
    for region in REGIONS:
        print(f"Scanning VPC Peering Connections in region: {region}")
        ec2 = boto3.client('ec2', region_name=region)
        try:
            peerings = ec2.describe_vpc_peering_connections()['VpcPeeringConnections']
        except Exception as e:
            print(f"Failed to retrieve VPC Peering Connections in {region}: {e}")
            continue
        for peering in peerings:
            peering_id = peering['VpcPeeringConnectionId']
            tags = {tag['Key']: tag['Value'] for tag in peering.get('Tags', [])}
            tag_value = tags.get(TAG_KEY)
            if tag_value == TAG_VALUE:
                message = f"Skipping VPC Peering: {peering_id} (already tagged)"
            elif tag_value:
                message = f"VPC Peering {peering_id} has conflicting tag value: {tag_value}"
            else:
                try:
                    ec2.create_tags(Resources=[peering_id], Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged VPC Peering: {peering_id}"
                except Exception as e:
                    message = f"Failed to tag VPC Peering: {peering_id}. Error: {str(e)}"
            print(message)
            csv_writer.writerow([region, peering_id, "VPCPeering", "", tag_value or TAG_VALUE, "", message])

def process_directory_service():
    for region in REGIONS:
        print(f"Scanning Directory Service in region: {region}")
        ds = boto3.client('ds', region_name=region)
        try:
            directories = ds.describe_directories()['DirectoryDescriptions']
        except Exception as e:
            print(f"Failed to retrieve directories in {region}: {e}")
            continue
        for directory in directories:
            directory_id = directory['DirectoryId']
            create_date = directory.get('LaunchTime', directory.get('StageLastUpdatedDateTime', datetime.min.replace(tzinfo=timezone.utc)))
            try:
                tags = {t['Key']: t['Value'] for t in ds.list_tags_for_resource(ResourceId=directory_id)['Tags']}
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping Directory: {directory_id} (already tagged)"
                elif tag_value:
                    message = f"Directory {directory_id} has conflicting tag value: {tag_value}"
                elif create_date >= CUTOFF:
                    ds.add_tags_to_resource(ResourceId=directory_id, Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged Directory: {directory_id}"
                else:
                    message = f"Skipping Directory: {directory_id} (too old: {create_date})"
            except Exception as e:
                message = f"Failed to tag Directory: {directory_id}. Error: {str(e)}"
            print(message)
            csv_writer.writerow([region, directory_id, "DirectoryService", "", tag_value or TAG_VALUE, create_date, message])
def process_fsx_filesystems():
    for region in REGIONS:
        print(f"Scanning FSx filesystems in region: {region}")
        fsx = boto3.client('fsx', region_name=region)
        try:
            filesystems = fsx.describe_file_systems()['FileSystems']
        except Exception as e:
            print(f"Failed to retrieve FSx filesystems in {region}: {e}")
            continue
        for fs in filesystems:
            fs_id = fs['FileSystemId']
            create_time = fs['CreationTime']
            try:
                tags = {t['Key']: t['Value'] for t in fs.get('Tags', [])}
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping FSx: {fs_id} (already tagged)"
                elif tag_value:
                    message = f"FSx {fs_id} has conflicting tag value: {tag_value}"
                elif create_time >= CUTOFF:
                    fsx.tag_resource(ResourceARN=fs['ResourceARN'], Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged FSx: {fs_id}"
                else:
                    message = f"Skipping FSx: {fs_id} (too old: {create_time})"
            except Exception as e:
                message = f"Failed to tag FSx: {fs_id}. Error: {str(e)}"
            print(message)
            csv_writer.writerow([region, fs_id, "FSx", "", tag_value or TAG_VALUE, create_time, message])
def process_waf_web_acls():
    print("Scanning WAFv2 Web ACLs (global and regional)")
    for scope in ['REGIONAL', 'CLOUDFRONT']:
        wafv2 = boto3.client('wafv2', region_name='us-east-1' if scope == 'CLOUDFRONT' else REGIONS[0])
        try:
            acls = wafv2.list_web_acls(Scope=scope)['WebACLs']
        except Exception as e:
            print(f"Failed to list WAFv2 Web ACLs ({scope}): {e}")
            continue
        for acl in acls:
            name = acl['Name']
            arn = acl['ARN']
            try:
                tags = {t['Key']: t['Value'] for t in wafv2.list_tags_for_resource(ResourceARN=arn)['TagInfoForResource']['TagList']}
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping WAF WebACL: {name} (already tagged)"
                elif tag_value:
                    message = f"WAF WebACL {name} has conflicting tag value: {tag_value}"
                else:
                    wafv2.tag_resource(ResourceARN=arn, Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged WAF WebACL: {name}"
            except Exception as e:
                message = f"Failed to tag WAF WebACL: {name}. Error: {str(e)}"
            print(message)
            csv_writer.writerow([scope, name, "WAFv2", "", tag_value or TAG_VALUE, "", message])
def process_guardduty_detectors():
    for region in REGIONS:
        print(f"Scanning GuardDuty Detectors in region: {region}")
        gd = boto3.client('guardduty', region_name=region)
        try:
            detectors = gd.list_detectors()['DetectorIds']
        except Exception as e:
            print(f"Failed to retrieve GuardDuty detectors in {region}: {e}")
            continue
        for detector_id in detectors:
            try:
                arn = f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}"
                tags = gd.list_tags_for_resource(ResourceArn=arn).get('Tags', {})
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping GuardDuty detector: {detector_id} (already tagged)"
                elif tag_value:
                    message = f"GuardDuty detector {detector_id} has conflicting tag value: {tag_value}"
                else:
                    gd.tag_resource(ResourceArn=arn, Tags={TAG_KEY: TAG_VALUE})
                    message = f"Successfully tagged GuardDuty detector: {detector_id}"
            except Exception as e:
                message = f"Failed to tag GuardDuty detector: {detector_id}. Error: {str(e)}"
            print(message)
            csv_writer.writerow([region, detector_id, "GuardDuty", "", tag_value or TAG_VALUE, "", message])
def process_storage_gateways():
    for region in REGIONS:
        print(f"Scanning Storage Gateways in region: {region}")
        sg = boto3.client('storagegateway', region_name=region)
        try:
            gateways = sg.list_gateways()['Gateways']
        except Exception as e:
            print(f"Failed to retrieve Storage Gateways in {region}: {e}")
            continue
        for gw in gateways:
            arn = gw['GatewayARN']
            gw_id = arn.split('/')[-1]
            try:
                tags = {tag['Key']: tag['Value'] for tag in sg.list_tags_for_resource(ResourceARN=arn)['Tags']}
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping Storage Gateway: {gw_id} (already tagged)"
                elif tag_value:
                    message = f"Storage Gateway {gw_id} has conflicting tag value: {tag_value}"
                else:
                    sg.add_tags_to_resource(ResourceARN=arn, Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged Storage Gateway: {gw_id}"
            except Exception as e:
                message = f"Failed to tag Storage Gateway: {gw_id}. Error: {str(e)}"
            print(message)
            csv_writer.writerow([region, gw_id, "StorageGateway", "", tag_value or TAG_VALUE, "", message])
def process_cloudtrail_trails():
    for region in REGIONS:
        print(f"Scanning CloudTrail trails in region: {region}")
        ct = boto3.client('cloudtrail', region_name=region)
        try:
            trails = ct.list_trails()['Trails']
        except Exception as e:
            print(f"Failed to retrieve CloudTrail trails in {region}: {e}")
            continue
        for trail in trails:
            arn = trail['TrailARN']
            name = trail['Name']
            try:
                tags = {tag['Key']: tag['Value'] for tag in ct.list_tags(ResourceIdList=[arn])['ResourceTagList'][0]['TagsList']}
                tag_value = tags.get(TAG_KEY)
                if tag_value == TAG_VALUE:
                    message = f"Skipping CloudTrail: {name} (already tagged)"
                elif tag_value:
                    message = f"CloudTrail {name} has conflicting tag value: {tag_value}"
                else:
                    ct.add_tags(ResourceId=arn, TagsList=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                    message = f"Successfully tagged CloudTrail: {name}"
            except Exception as e:
                message = f"Failed to tag CloudTrail: {name}. Error: {str(e)}"
            print(message)
            csv_writer.writerow([region, name, "CloudTrail", "", tag_value or TAG_VALUE, "", message])
def process_sns_topics():
    for region in REGIONS:
        print(f"Scanning SNS topics in region: {region}")
        sns = boto3.client('sns', region_name=region)
        try:
            topics = sns.list_topics().get('Topics', [])
        except Exception as e:
            print(f"Failed to retrieve SNS topics in {region}: {e}")
            continue

        for topic in topics:
            topic_arn = topic['TopicArn']
            try:
                # Get existing tags
                tags = {tag['Key']: tag['Value'] for tag in sns.list_tags_for_resource(ResourceArn=topic_arn).get('Tags', [])}
                tag_value = tags.get(TAG_KEY)

                if tag_value == TAG_VALUE:
                    message = f"Skipping SNS topic: {topic_arn} (already tagged)"
                    print(message)
                    csv_writer.writerow([region, topic_arn, "SNS", "Already Tagged", tag_value, "", message])
                    continue
                elif tag_value:
                    message = f"SNS topic {topic_arn} has conflicting tag value: {tag_value}"
                    print(message)
                    csv_writer.writerow([region, topic_arn, "SNS", "Conflicting Tag", tag_value, "", message])
                    continue

                # Add the tag
                sns.tag_resource(ResourceArn=topic_arn, Tags=[{'Key': TAG_KEY, 'Value': TAG_VALUE}])
                message = f"Successfully tagged SNS topic: {topic_arn}"
                print(message)
                csv_writer.writerow([region, topic_arn, "SNS", "Tagged", TAG_VALUE, "", message])

            except Exception as e:
                message = f"Failed to tag SNS topic: {topic_arn}. Error: {str(e)}"
                print(message)
                csv_writer.writerow([region, topic_arn, "SNS", "Failed", "", "", message])
# === Run All ===
def run_all():
    process_ec2_instances()
    process_lambda_functions()
    process_rds_instances()
    process_ebs_volumes()
    process_s3_buckets()
    process_ecs_clusters()
    process_snapshots()
    process_ami_images()
    process_elbs()
    process_secrets()
    process_sqs_queues()
    process_kms_keys()
    process_api_gateways()
    process_ecr_repositories()
    process_vpcs()
    process_cloudwatch_log_groups()
    process_cloudwatch_alarms()
    process_config_rules()
    process_nat_gateways()
    process_internet_gateways()
    process_vpc_peerings()
    process_directory_service()
    process_fsx_filesystems()
    process_waf_web_acls()
    process_guardduty_detectors()
    process_storage_gateways()
    process_cloudtrail_trails()
    process_sns_topics()
    
    csvfile.close()
    print(f"\nReport saved to: {csv_filename}")



# === Main Execution ===
if __name__ == "__main__":
    run_all()