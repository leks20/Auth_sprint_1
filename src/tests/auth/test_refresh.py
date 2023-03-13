import json

import pytest


@pytest.mark.parametrize(
    ("email", "password", "expected_status_code", "expected_result"),
    [
        ("test_refresh@example.com", "oqwerrt", 200, {"status": "success"}),
    ],
)
def test_refresh(
    client,
    email,
    password,
    expected_status_code,
    expected_result,
):
    user = {"email": email, "password": password}

    client.post(
        "/auth/register",
        data=user,
    )

    response_login = client.post(
        "/auth/login",
        data=user,
    )

    refresh_token = json.loads(response_login.data)["refresh_token"]

    response = client.post(
        "/auth/refresh",
        headers={
            "Authorization": f"Bearer {refresh_token}",
        },
    )

    assert response.status_code == expected_status_code
    assert "access_token" in json.loads(response.data)
