import json
import pytest


@pytest.mark.parametrize(
    ("email", "password", "expected_status_code", "expected_result"),
    [
        ("test_logout_post@example.com", "oqwerrt", 200, "token successfully revoked"),
    ],
)
def test_logout(
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
    access_token = json.loads(response_login.data)["access_token"]

    response = client.get(
        "/auth/logout",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )
    assert response.status_code == expected_status_code
    assert expected_result in json.loads(response.data)["msg"]
