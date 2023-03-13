import json
import pytest


@pytest.mark.parametrize(
    ("role_data", "expected_status_code", "expected_result"),
    [
        ({"name": "Test get roles"}, 200, "Test get roles"),
    ],
)
def test_get_roles(
    client, access_token, role_data, expected_status_code, expected_result
):
    response_post = client.post(
        "roles/",
        data=role_data,
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )
    assert response_post.status_code == 201

    response_get = client.get(
        "roles/",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )
    data = json.loads(response_get.data)
    assert len(data) > 0
    assert response_get.status_code == expected_status_code
    assert data[-1]["name"] == expected_result
