import json

import pytest


@pytest.mark.parametrize(
    ("email", "password", "expected_status_code"),
    [
        ("test_login_post@example.com", "oqwerrt", 200),
    ],
)
def test_login_post(
    client,
    email,
    password,
    expected_status_code,
):
    user = {"email": email, "password": password}

    client.post(
        "/auth/register",
        data=user,
    )
    response = client.post(
        "/auth/login",
        data=user,
    )

    assert response.status_code == expected_status_code
    assert "access_token" in json.loads(response.data)
