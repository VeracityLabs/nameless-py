import pytest
from nameless_py.native.library.server.monolithic import NativeMonolithicIssuer
from nameless_py.native.library.types.attributes import NativeAttributeList
from nameless_py.native.library.client.credential_builder import (
    NativeCredentialBuilder,
    NativeCredentialHolder,
)
import os


@pytest.fixture
def issuer() -> NativeMonolithicIssuer:
    """Create a NativeMonolithicIssuer instance with 5 max attributes"""
    return NativeMonolithicIssuer(5)


@pytest.fixture
def attribute_list() -> NativeAttributeList:
    """Create a NativeAttributeList with some test attributes"""
    attributes = NativeAttributeList()

    attributes.append_public_attribute(b"public_attr_1")
    attributes.append_private_attribute(b"private_attr_1")
    attributes.append_public_attribute(b"public_attr_2")
    return attributes


@pytest.fixture
def test_credential_builder() -> NativeCredentialBuilder:
    # Create an issuer
    issuer = NativeMonolithicIssuer(5)

    # Create an attribute list
    attribute_list = NativeAttributeList()
    attribute_list.append_public_attribute(b"public_attr_1")
    attribute_list.append_private_attribute(b"private_attr_1")
    attribute_list.append_public_attribute(b"public_attr_2")

    # Create a NativeCredentialBuilder instance with the given issuer and attribute list
    return NativeCredentialBuilder(issuer, attribute_list)


@pytest.fixture
def test_credential_issuing() -> NativeCredentialHolder:
    # Create an issuer
    issuer = NativeMonolithicIssuer(5)

    # Create an attribute list
    attribute_list = NativeAttributeList()
    attribute_list.append_public_attribute(b"public_attr_1")
    attribute_list.append_private_attribute(b"private_attr_1")
    attribute_list.append_public_attribute(b"public_attr_2")

    # Create a NativeCredentialBuilder instance with the given issuer and attribute list
    builder = NativeCredentialBuilder(
        {
            "group_parameters": issuer.get_group_parameters(),
            "attribute_list": attribute_list,
            "credential_secret": None,
        }
    )

    # Create a credential request
    credential_request = builder.request_credential()

    # Issue the credential
    requested_credential = issuer.issue(credential_request)

    # Import the credential
    return builder.create_holder(requested_credential)


@pytest.fixture
def test_conditional_issuance() -> NativeCredentialHolder:
    # Create an issuer
    issuer = NativeMonolithicIssuer(5)

    # Create an attribute list
    attribute_list = NativeAttributeList()
    attribute_list.append_public_attribute(b"public_attr_1")
    attribute_list.append_private_attribute(b"private_attr_1")
    attribute_list.append_public_attribute(b"public_attr_2")

    # Create a NativeCredentialBuilder instance with the given issuer and attribute list
    builder = NativeCredentialBuilder(
        {
            "group_parameters": issuer.get_group_parameters(),
            "attribute_list": attribute_list,
            "credential_secret": None,
        }
    )

    # Create a credential request
    credential_request = builder.request_credential()
    public_attributes = credential_request.get_public_attributes()

    # TODO: update test when it's possible to inspect public attributes, and know the index of the private attribute

    # Issue the credential
    requested_credential = issuer.issue(credential_request)

    # Import the credential
    return builder.create_holder(requested_credential)
