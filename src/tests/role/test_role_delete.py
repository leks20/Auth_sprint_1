import json
import pytest


@pytest.mark.parametrize(
    ("role_data", "expected_status_code", "expected_result"),
    [
        ({"name": "Test delete role"}, 200, "Role deleted successfully"),
    ],
)
def test_delete_role(
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
    role_id = json.loads(response_post.data)["id"]

    response_get = client.delete(
        f"roles/{role_id}",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    data = json.loads(response_get.data)
    assert response_get.status_code == expected_status_code
    assert data["message"] == expected_result
