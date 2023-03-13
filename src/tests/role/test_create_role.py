import json
import pytest


@pytest.mark.parametrize(
    ("role_data", "expected_status_code", "expected_result"),
    [
        ({"name": "Test Role"}, 201, "Test Role"),
        ({}, 400, {"error": "Role name is required"}),
    ],
)
def test_create_role(
    client, access_token, role_data, expected_status_code, expected_result
):
    response = client.post(
        "roles/",
        data=role_data,
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert response.status_code == expected_status_code
    if response.status_code == 201:
        assert json.loads(response.data)["name"] == expected_result
    else:
        assert json.loads(response.data) == expected_result
