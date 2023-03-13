import pytest


@pytest.mark.parametrize(
    ("email", "password", "expected_status_code", "expected_result"),
    [
        ("ex@example.com", "oqwerrt", 201, {"status": "success"}),
        (
            "ex@example.com",
            "oqwerrt",
            400,
            {"message": "User already exist!", "status": "error"},
        ),
    ],
)
def test_register(
    client,
    email,
    password,
    expected_status_code,
    expected_result,
):
    url = "/auth/register"
    user = {"email": email, "password": password}
    response = client.post(
        url,
        data=user,
    )
    assert response.status_code == expected_status_code
    assert response.json == expected_result
