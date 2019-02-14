from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
import unittest

import boto3
from botocore.exceptions import ClientError

from moto import mock_iam
from awacs.helpers.trust import get_ecs_assumerole_policy

from stacker.hooks.iam import (
    create_ecs_service_role,
    _get_cert_arn_from_response,
    ensure_server_cert_exists,
)

from ..factories import (
    mock_context,
    mock_provider,
)


REGION = "us-east-1"

MOCK_CERT = """-----BEGIN CERTIFICATE-----
MIIBpzCCARACCQCY5yOdxCTrGjANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQKDAxt
b3RvIHRlc3RpbmcwIBcNMTgxMTA1MTkwNTIwWhgPMjI5MjA4MTkxOTA1MjBaMBcx
FTATBgNVBAoMDG1vdG8gdGVzdGluZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEA1Jn3g2h7LD3FLqdpcYNbFXCS4V4eDpuTCje9vKFcC3pi/01147X3zdfPy8Mt
ZhKxcREOwm4NXykh23P9KW7fBovpNwnbYsbPqj8Hf1ZaClrgku1arTVhEnKjx8zO
vaR/bVLCss4uE0E0VM1tJn/QGQsfthFsjuHtwx8uIWz35tUCAwEAATANBgkqhkiG
9w0BAQsFAAOBgQBWdOQ7bDc2nWkUhFjZoNIZrqjyNdjlMUndpwREVD7FQ/DuxJMj
FyDHrtlrS80dPUQWNYHw++oACDpWO01LGLPPrGmuO/7cOdojPEd852q5gd+7W9xt
8vUH+pBa6IBLbvBp+szli51V3TLSWcoyy4ceJNQU2vCkTLoFdS0RLd/7tQ==
-----END CERTIFICATE-----"""


class TestIAMHooks(unittest.TestCase):

    def setUp(self):
        self.context = mock_context(namespace="fake")
        self.provider = mock_provider(region=REGION)

    def test_get_cert_arn_from_response(self):
        arn = "fake-arn"
        # Creation response
        response = {
            "ServerCertificateMetadata": {
                "Arn": arn
            }
        }

        self.assertEqual(_get_cert_arn_from_response(response), arn)

        # Existing cert response
        response = {"ServerCertificate": response}
        self.assertEqual(_get_cert_arn_from_response(response), arn)

    def test_create_service_role(self):
        role_name = "ecsServiceRole"
        policy_name = "AmazonEC2ContainerServiceRolePolicy"
        with mock_iam():
            client = boto3.client("iam", region_name=REGION)

            with self.assertRaises(ClientError):
                client.get_role(RoleName=role_name)

            self.assertTrue(
                create_ecs_service_role(
                    context=self.context,
                    provider=self.provider,
                )
            )

            role = client.get_role(RoleName=role_name)

            self.assertIn("Role", role)
            self.assertEqual(role_name, role["Role"]["RoleName"])
            client.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )

    def test_create_service_role_already_exists(self):
        role_name = "ecsServiceRole"
        policy_name = "AmazonEC2ContainerServiceRolePolicy"
        with mock_iam():
            client = boto3.client("iam", region_name=REGION)
            client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=get_ecs_assumerole_policy().to_json()
            )

            self.assertTrue(
                create_ecs_service_role(
                    context=self.context,
                    provider=self.provider,
                )
            )

            role = client.get_role(RoleName=role_name)

            self.assertIn("Role", role)
            self.assertEqual(role_name, role["Role"]["RoleName"])
            client.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )

    def test_ensure_server_cert_exists(self):
        with mock_iam():
            client = boto3.client("iam", region_name=REGION)
            client.create_user(UserName="testing")
            test_cert_name = "MOCK_CERTIFICATE"
            client.upload_signing_certificate(UserName="testing", CertificateBody=MOCK_CERT)["Certificate"]

            value = ensure_server_cert_exists(
                context=self.context,
                provider=self.provider,
                cert_name=test_cert_name
            )

            self.assertEqual(value["status"], "exists")
            self.assertEqual(value["cert_name"], test_cert_name)
            print(value["cert_arn"])

    # def test_server_missing(self):
    #     value = ensure_server_cert_exists(
    #         context=self.context,
    #         provider=self.provider,
    #         prompt=True
    #     )