import pytest

from src.rotation.providers.database import PostgreSQLProvider, _generate_password


class TestGeneratePassword:
    def test_default_length(self) -> None:
        password = _generate_password()
        assert len(password) == 32

    def test_custom_length(self) -> None:
        password = _generate_password(length=64)
        assert len(password) == 64

    def test_contains_mixed_characters(self) -> None:
        password = _generate_password(length=100)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        assert has_upper and has_lower and has_digit

    def test_different_each_call(self) -> None:
        passwords = {_generate_password() for _ in range(10)}
        assert len(passwords) == 10


class TestPostgreSQLProviderValidation:
    def test_valid_role_name_accepted(self) -> None:
        provider = PostgreSQLProvider(
            host="localhost",
            port=5432,
            admin_user="admin",
            admin_password="pass",
            target_user="app_user",
        )
        assert provider.provider_name == "postgresql"

    def test_invalid_role_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid PostgreSQL role name"):
            PostgreSQLProvider(
                host="localhost",
                port=5432,
                admin_user="admin",
                admin_password="pass",
                target_user="admin; DROP ROLE",
            )

    def test_empty_role_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid PostgreSQL role name"):
            PostgreSQLProvider(
                host="localhost",
                port=5432,
                admin_user="admin",
                admin_password="pass",
                target_user="",
            )

    def test_role_name_starting_with_digit_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid PostgreSQL role name"):
            PostgreSQLProvider(
                host="localhost",
                port=5432,
                admin_user="admin",
                admin_password="pass",
                target_user="1user",
            )

    def test_role_name_too_long_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid PostgreSQL role name"):
            PostgreSQLProvider(
                host="localhost",
                port=5432,
                admin_user="admin",
                admin_password="pass",
                target_user="a" * 64,
            )
