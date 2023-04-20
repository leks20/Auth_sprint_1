import json
import pytest


@pytest.mark.parametrize(
    ("email", "password", "expected_status_code"),
    [
        ("test_login_history@example.com", "oqwerrt", 200),
    ],
)
def test_login_history(
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
    response_login = client.post(
        "/auth/login",
        data=user,
    )

    access_token = json.loads(response_login.data)["access_token"]

    response = client.get(
        "/auth/login_history",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )
    assert response.status_code == expected_status_code
    assert "history" in json.loads(response.data)
