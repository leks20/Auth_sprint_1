import json
import pytest


@pytest.mark.parametrize(
    ("role_data", "new_role_data", "expected_status_code", "expected_result"),
    [
        ({"name": "Old role"}, "New role", 200, "New role"),
    ],
)
def test_update_role(
    client,
    access_token,
    role_data,
    new_role_data,
    expected_status_code,
    expected_result,
):
    response_post = client.post(
        "roles/",
        data=role_data,
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )
    assert response_post.status_code == 201
    role_id = json.loads(response_post.data)["id"]

    response_get = client.put(
        "roles/change_name",
        data={"role_id": role_id, "new_name": new_role_data},
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    data = json.loads(response_get.data)
    assert response_get.status_code == expected_status_code
    assert data["id"] == role_id
    assert data["name"] == expected_result
