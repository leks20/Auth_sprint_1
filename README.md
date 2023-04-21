## Запуск приложения
docker-compose up --build 

## Миграции
docker exec -it auth_app bash
flask db init
flask db migrate -m "Initial migration"

Добавить в функцию upgrade():

    op.execute("""
    CREATE TABLE login_history_web PARTITION OF login_history FOR VALUES IN ('web');
    CREATE TABLE login_history_mobile PARTITION OF login_history FOR VALUES IN ('mobile');
    CREATE TABLE login_history_other PARTITION OF login_history FOR VALUES IN ('other');
    """)

    op.execute("""
    CREATE TABLE users_0 PARTITION OF users FOR VALUES WITH (MODULUS 4, REMAINDER 0);
    CREATE TABLE users_1 PARTITION OF users FOR VALUES WITH (MODULUS 4, REMAINDER 1);
    CREATE TABLE users_2 PARTITION OF users FOR VALUES WITH (MODULUS 4, REMAINDER 2);
    CREATE TABLE users_3 PARTITION OF users FOR VALUES WITH (MODULUS 4, REMAINDER 3);

    """)

Добавить в функцию downgrade():

    op.execute("""
    DROP TABLE IF EXISTS login_history_web;
    DROP TABLE IF EXISTS login_history_mobile;
    DROP TABLE IF EXISTS login_history_other;
    """)
    
    op.execute("""
    DROP TABLE IF EXISTS users_1;
    DROP TABLE IF EXISTS users_2;
    DROP TABLE IF EXISTS users_3;
    DROP TABLE IF EXISTS users_4;
    """) 

flask db upgrade

## SSL
При локальной разработке и тестировании  необходимо с помощью mkcert создать и положить в корневую папку ssl ключи: cert.pem и key.pem

## Swagger
https://localhost:5000/apidocs/
