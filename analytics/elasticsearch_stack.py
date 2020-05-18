from aws_cdk import (
    aws_elasticsearch as _elasticsearch,
    aws_cognito,
    aws_iam as iam,
    core)

import random
import string

DOMAIN = _elasticsearch.CfnDomain


class ElasticsearchStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, props, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

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

        cognito_options = DOMAIN.CognitoOptionsProperty(enabled=True, user_pool_id=user_pool.user_pool_id,
                                                        identity_pool_id=identity_pool.ref,
                                                        role_arn=f"arn:aws:iam::{core.Aws.ACCOUNT_ID}:role/service-role/CognitoAccessForAmazonES")

        ebs_options = DOMAIN.EBSOptionsProperty(ebs_enabled=True, volume_size=10, volume_type='gp2')
        elasticsearch_cluster_config = DOMAIN.ElasticsearchClusterConfigProperty(instance_count=1,
                                                                                 instance_type='r5.large.elasticsearch')
        encryption_at_rest_options = DOMAIN.EncryptionAtRestOptionsProperty(enabled=True)
        node_to_node_encryption_options = DOMAIN.NodeToNodeEncryptionOptionsProperty(enabled=True)
        snapshot_options = DOMAIN.SnapshotOptionsProperty(automated_snapshot_start_hour=0)

        es_policy_statement = iam.PolicyStatement(actions=['es:ESHttp*'],
                                                  resources=[
                                                      f"arn:aws:es:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:domain/{props['projectName'].lower()}/*"])

        es_policy_statement.add_account_root_principal()

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
