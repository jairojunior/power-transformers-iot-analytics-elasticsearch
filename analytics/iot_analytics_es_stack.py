from aws_cdk import (
    aws_iotanalytics as _iotanalytics,
    aws_s3 as s3,
    aws_iam as iam,
    aws_elasticsearch as _elasticsearch,
    aws_lambda as _lambda,
    aws_cognito,
    aws_dynamodb,
    aws_s3_notifications,
    core)

import random
import string
from custom_resource.load_es_index_custom_resource import LoadESIndexCustomResource
from custom_resource.load_kibana_dashboards_custom_resource import LoadKibanaDashboardsCustomResource
from custom_resource.load_ddb_data_custom_resource import LoadDDBDataCustomResource

CHANNEL = _iotanalytics.CfnChannel
DATASTORE = _iotanalytics.CfnDatastore
PIPELINE = _iotanalytics.CfnPipeline
DATASET = _iotanalytics.CfnDataset
DOMAIN = _elasticsearch.CfnDomain


class IotAnalyticsEsStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, props, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        power_transformers = aws_dynamodb.Table(
            self, "PowerTransformers",
            table_name="PowerTransformers",
            partition_key=aws_dynamodb.Attribute(
                name="name",
                type=aws_dynamodb.AttributeType.STRING
            ),
            removal_policy=core.RemovalPolicy.DESTROY
        )

        function = _lambda.Function(self, "power_transformers_data_enrichment",
                                    function_name="power_transformers_data_enrichment",
                                    runtime=_lambda.Runtime.PYTHON_3_7,
                                    handler="lambda_function.handler",
                                    code=_lambda.Code.asset("./lambda/data-enrichment"))

        function.add_environment('TABLE_NAME', power_transformers.table_name)
        function.add_to_role_policy(
            iam.PolicyStatement(actions=['dynamodb:GetItem'], resources=[f"{power_transformers.table_arn}"],
                                effect=iam.Effect.ALLOW))

        function.add_permission(principal=iam.ServicePrincipal('iotanalytics.amazonaws.com'),
                                action='lambda:InvokeFunction', id='pt-iot-analytics')

        bucket = s3.Bucket(self, 'PowerTransformersTelemetryBucket',
                           bucket_name=f"{props['projectName'].lower()}-{core.Aws.ACCOUNT_ID}",
                           removal_policy=core.RemovalPolicy.DESTROY)

        output_bucket = s3.Bucket(self, 'PowerTransformersProcessedDataBucket',
                                  bucket_name=f"{props['projectName'].lower()}-output-{core.Aws.ACCOUNT_ID}",
                                  removal_policy=core.RemovalPolicy.DESTROY)

        s3_role = iam.Role(self, "IotAnalyticsS3Role",
                           assumed_by=iam.ServicePrincipal("iotanalytics.amazonaws.com"),
                           managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name('AmazonS3FullAccess')]
                           )

        # s3_role.add_to_policy(iam.PolicyStatement(actions=["s3:PutObject", "s3:DeleteObject", "s3:GetBucketLocation"],
        #                       resources=[f"{bucket.bucket_arn}", f"{bucket.bucket_arn}/*"], effect=iam.Effect.ALLOW))

        s3_output_role = iam.Role(self, "IotAnalyticsS3OutputRole",
                                  assumed_by=iam.ServicePrincipal("iotanalytics.amazonaws.com"),
                                  managed_policies=[
                                      iam.ManagedPolicy.from_aws_managed_policy_name('AmazonS3FullAccess')],
                                  )

        # s3_output_role.add_to_policy(iam.PolicyStatement(actions=["s3:PutObject", "s3:DeleteObject", "s3:GetBucketLocation"],
        #                       resources=[f"{output_bucket.bucket_arn}", f"{output_bucket.bucket_arn}/*"], effect=iam.Effect.ALLOW))

        project_name = props['projectName'].lower().replace('-', '_')

        channel_name = f"{project_name}_channel"
        datastore_name = f"{project_name}_datastore"

        channel_s3 = CHANNEL.CustomerManagedS3Property(bucket=bucket.bucket_name, key_prefix='raw/',
                                                       role_arn=s3_role.role_arn)
        channel_storage = CHANNEL.ChannelStorageProperty(customer_managed_s3=channel_s3)

        CHANNEL(self, 'iot_channel',
                channel_name=channel_name,
                channel_storage=channel_storage)

        datastore_s3 = DATASTORE.CustomerManagedS3Property(bucket=bucket.bucket_name, key_prefix='processed/',
                                                           role_arn=s3_role.role_arn)

        datastore_storage = DATASTORE.DatastoreStorageProperty(customer_managed_s3=datastore_s3)

        datastore = DATASTORE(self, 'iot_datastore',
                              datastore_name=datastore_name,
                              datastore_storage=datastore_storage)

        channel_activity = PIPELINE.ChannelProperty(name='ChannelActivity', channel_name=channel_name,
                                                    next='LambdaActivity')
        lambda_activity = PIPELINE.LambdaProperty(name='LambdaActivity',
                                                  lambda_name='power_transformers_data_enrichment',
                                                  next='DatastoreActivity', batch_size=10)
        datastore_activity = PIPELINE.DatastoreProperty(name='DatastoreActivity', datastore_name=datastore_name)

        pipeline_activities = PIPELINE.ActivityProperty(channel=channel_activity, lambda_=lambda_activity,
                                                        datastore=datastore_activity)

        pipeline = PIPELINE(self, 'iot_pipeline',
                            pipeline_name=f"{project_name}_pipeline",
                            pipeline_activities=[pipeline_activities])

        pipeline.add_depends_on(datastore)

        query_action = DATASET.QueryActionProperty(sql_query=f"SELECT * FROM {datastore_name}")
        action = DATASET.ActionProperty(query_action=query_action, action_name='sqlAction')
        schedule_expression = DATASET.ScheduleProperty(schedule_expression='cron(1/5 * * * ? *)')
        trigger_schedule = DATASET.TriggerProperty(schedule=schedule_expression)

        dataset_s3_destination = DATASET.S3DestinationConfigurationProperty(bucket=output_bucket.bucket_name,
                                                                            key='dataset/Version/!{iotanalytics:scheduleTime}_!{iotanalytics:versionId}.csv',
                                                                            role_arn=s3_output_role.role_arn)

        dataset_destination = DATASET.DatasetContentDeliveryRuleDestinationProperty(
            s3_destination_configuration=dataset_s3_destination)

        content_delivery_rules = DATASET.DatasetContentDeliveryRuleProperty(destination=dataset_destination)

        dataset = DATASET(self, 'iot_dataset',
                          dataset_name=f"{project_name}_dataset",
                          actions=[action],
                          triggers=[trigger_schedule],
                          content_delivery_rules=[content_delivery_rules])

        dataset.add_depends_on(datastore)

        user_pool = aws_cognito.UserPool(self, 'kibanaUserPool', self_sign_up_enabled=False,
                                         sign_in_aliases=aws_cognito.SignInAliases(username=True, email=True))

        aws_cognito.CfnUserPoolDomain(self, 'userPoolDomain', user_pool_id=user_pool.user_pool_id,
                                      domain=f"{props['projectName'].lower()}-{''.join(random.choices(string.ascii_lowercase + string.digits, k=6))}")

        user_pool_client = aws_cognito.UserPoolClient(self, 'kibanaClientId', user_pool=user_pool, generate_secret=True)

        identity_provider = aws_cognito.CfnIdentityPool.CognitoIdentityProviderProperty(
            client_id=user_pool_client.user_pool_client_id, provider_name=user_pool.user_pool_provider_name)

        identity_pool = aws_cognito.CfnIdentityPool(self, 'identityPool',
                                                    allow_unauthenticated_identities=False,
                                                    cognito_identity_providers=[identity_provider])

        # Apply least privilege
        cognito_authenticated_role = iam.Role(self, "CognitoAuthRole",
                                              assumed_by=iam.FederatedPrincipal("cognito-identity.amazonaws.com",
                                                                                assume_role_action='sts:AssumeRoleWithWebIdentity',
                                                                                conditions={'StringEquals': {
                                                                                    'cognito-identity.amazonaws.com:aud': identity_pool.ref},
                                                                                    'ForAnyValue:StringLike': {
                                                                                        'cognito-identity.amazonaws.com:amr': 'authenticated'}}
                                                                                ),
                                              managed_policies=[
                                                  iam.ManagedPolicy.from_aws_managed_policy_name('AmazonESFullAccess')]
                                              )

        aws_cognito.CfnIdentityPoolRoleAttachment(self, 'identityPoolRoleAttachment',
                                                  identity_pool_id=identity_pool.ref,
                                                  roles={'authenticated': cognito_authenticated_role.role_arn})

        cognito_options = DOMAIN.CognitoOptionsProperty(enabled=True, user_pool_id=user_pool.user_pool_id,
                                                        identity_pool_id=identity_pool.ref,
                                                        role_arn=f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:role/service-role/CognitoAccessForAmazonES")

        ebs_options = DOMAIN.EBSOptionsProperty(ebs_enabled=True, volume_size=10, volume_type='gp2')
        elasticsearch_cluster_config = DOMAIN.ElasticsearchClusterConfigProperty(instance_count=1,
                                                                                 instance_type='r5.large.elasticsearch')
        encryption_at_rest_options = DOMAIN.EncryptionAtRestOptionsProperty(enabled=True)
        node_to_node_encryption_options = DOMAIN.NodeToNodeEncryptionOptionsProperty(enabled=True)
        snapshot_options = DOMAIN.SnapshotOptionsProperty(automated_snapshot_start_hour=0)

        es_domain_arn = f"arn:aws:es:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:domain/{props['projectName'].lower()}/*"

        es_policy_statement = iam.PolicyStatement(actions=['es:*'],
                                                  resources=[es_domain_arn])

        es_policy_statement.add_arn_principal(cognito_authenticated_role.role_arn)

        policy_document = iam.PolicyDocument()

        policy_document.add_statements(es_policy_statement)

        domain = DOMAIN(self, 'elasticsearch',
                        domain_name=f"{props['projectName'].lower()}",
                        cognito_options=cognito_options,
                        ebs_options=ebs_options,
                        elasticsearch_cluster_config=elasticsearch_cluster_config,
                        encryption_at_rest_options=encryption_at_rest_options,
                        node_to_node_encryption_options=node_to_node_encryption_options,
                        snapshot_options=snapshot_options,
                        elasticsearch_version='6.8',
                        access_policies=policy_document)

        function = _lambda.Function(self, "load_data_from_s3_to_es",
                                    function_name="load_data_from_s3_to_es",
                                    runtime=_lambda.Runtime.PYTHON_3_7,
                                    handler="lambda_function.handler",
                                    code=_lambda.Code.asset("./lambda/load-data-from-s3-to-es.zip"))

        function.add_environment('ES_HOST', domain.attr_domain_endpoint)
        function.add_environment('ES_REGION', f"{core.Aws.REGION}")

        function.add_to_role_policy(
            iam.PolicyStatement(actions=['es:ESHttpPost'], resources=[es_domain_arn], effect=iam.Effect.ALLOW))
        function.add_to_role_policy(
            iam.PolicyStatement(actions=['s3:GetObject'], resources=[f"{output_bucket.bucket_arn}/*"],
                                effect=iam.Effect.ALLOW))

        notification = aws_s3_notifications.LambdaDestination(function)

        output_bucket.add_event_notification(s3.EventType.OBJECT_CREATED, notification)

        load_ddb_custom_resource = LoadDDBDataCustomResource(self, "LoadDDBData",
                                                             table_name=power_transformers.table_name,
                                                             table_arn=power_transformers.table_arn)

        load_ddb_custom_resource.node.add_dependency(power_transformers)

        load_es_index_custom_resource = LoadESIndexCustomResource(self, "LoadESIndex",
                                                                  es_host=domain.attr_domain_endpoint,
                                                                  es_region=f"{core.Aws.REGION}",
                                                                  es_domain_arn=es_domain_arn)

        load_es_index_custom_resource.node.add_dependency(domain)

        # load_kibana_dashboards_custom_resource = LoadKibanaDashboardsCustomResource(self, "LoadKibanaDashboards",
        #                                                           es_host=domain.attr_domain_endpoint,
        #                                                           es_region=f"{core.Aws.REGION}",
        #                                                           es_domain_arn=es_domain_arn)
        #
        # load_kibana_dashboards_custom_resource.node.add_dependency(domain)
