"""
Shared pytest fixtures.

conftest.py is auto-discovered by pytest — anything here is available
to every test file without needing to import it.
"""

import os
import pytest


@pytest.fixture(scope="function")
def aws_credentials():
    """
    Fake AWS credentials so moto-mocked tests never accidentally
    require or touch real AWS credentials.
    """
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "ap-south-1"