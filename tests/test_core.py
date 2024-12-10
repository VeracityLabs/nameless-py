import pytest
from nameless_py.native.library.server.monolithic import NativeMonolithicIssuer
from nameless_py.native.library.types.attributes import NativeAttributeList
from nameless_py.native.library.client.credential_builder import (
    NativeCredentialBuilder,
    NativeCredentialHolder,
)
import os


def test_issuer() -> None:
    """Test creating a NativeMonolithicIssuer instance with 5 max attributes.

    Tests that a NativeMonolithicIssuer can be instantiated with a max attribute count of 5.
    """
    issuer = NativeMonolithicIssuer(5)
    assert isinstance(issuer, NativeMonolithicIssuer)


def test_attribute_list() -> None:
    """Test creating a NativeAttributeList with test attributes.

    Tests that a NativeAttributeList can be created and populated with both public and private attributes.
    """
    attributes = NativeAttributeList()
    attributes.append_public_attribute(b"public_attr_1")
    attributes.append_private_attribute(b"private_attr_1")
    attributes.append_public_attribute(b"public_attr_2")
    assert isinstance(attributes, NativeAttributeList)


def test_credential_builder() -> None:
    """Test creating a NativeCredentialBuilder.

    Tests that a NativeCredentialBuilder can be instantiated with an issuer and attribute list.
    """
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
    assert isinstance(builder, NativeCredentialBuilder)


def test_credential_issuing() -> None:
    """Test the full credential issuance flow.

    Tests that credentials can be requested, issued and imported into a holder.
    """
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

    print("Public Attributes, JSON: ", credential_request.get_public_attributes().export_json())

    # Issue the credential
    requested_credential = issuer.issue(credential_request)

    # Import the credential
    holder = builder.create_holder(requested_credential)
    assert isinstance(holder, NativeCredentialHolder)


def test_conditional_issuance() -> None:
    """Test conditional credential issuance.

    Tests that credentials can be issued with conditions based on public attributes.
    """
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
    assert isinstance(
        builder.create_holder(requested_credential), NativeCredentialHolder
    )


def test_monolithic_issuer() -> None:
    """Test basic NativeMonolithicIssuer instantiation.

    Tests that a NativeMonolithicIssuer can be created with a max attribute count of 2.
    """
    issuer = NativeMonolithicIssuer(2)
    assert issuer is not None
