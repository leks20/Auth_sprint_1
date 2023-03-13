import json
import pytest


@pytest.mark.parametrize(
    (
        "email",
        "old_password",
        "new_password",
        "expected_status_code",
        "expected_result",
    ),
    [
        (
            "change-password@example.com",
            "oqwerrt",
            "oqwerrt2",
            200,
            {"message": "Password changed successfully"},
        ),
    ],
)
def test_change_password(
    client,
    email,
    old_password,
    new_password,
    expected_status_code,
    expected_result,
):
    user = {"email": email, "password": old_password}
    change_password = {"new_password": new_password, "old_password": old_password}

    client.post(
        "/auth/register",
        data=user,
    )

    response_login = client.post(
        "/auth/login",
        data=user,
    )

    access_token = json.loads(response_login.data)["access_token"]

    response = client.patch(
        "/auth/change_password",
        data=change_password,
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == expected_status_code
    assert json.loads(response.data) == expected_result
