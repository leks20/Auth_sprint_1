import json
import pytest


@pytest.mark.parametrize(
    ("role_data", "expected_status_code", "expected_result"),
    [
        ({"name": "Test get roleby id"}, 200, "Test get roleby id"),
    ],
)
def test_get_role_by_id(
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

    response_get = client.get(
        f"roles/{role_id}",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )
    data = json.loads(response_get.data)
    assert response_get.status_code == expected_status_code
    assert data["id"] == role_id
    assert data["name"] == expected_result
