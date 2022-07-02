# Golang REST API JWT

This is a Lemonilo Backend Test

## Usage

Customize your Database: Change the file connection to your database

For Postgresql, add
```
gorm.Open(postgres.Open("user=iko password=iko dbname=lemonilo port=5432 sslmode=disable")
```

```
# Make sure the database has been created

# Run the webserver on port 3000
go run main.go
```

## Routes

```
@All Api endpoints can be seen in Postman Collection

# Public
POST   /api/login
@body: email, password

POST   /api/register
@body: email, password, address

# Protected (session_cookie_jwt)

# GET table users
GET   /api/user -> for get session jwt
GET   /api/users -> for get all users

PUT   /api/update/
@body: user_id, ?email, ?address, ?password

DELETE  /api/delete
@body: user_id

# Logout
POST    /api/logout

```
