# Eanrnit

## Curl Examples
```bash
# register a parent
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Parent",
    "email": "parent@example.com",
    "password": "testpass",
    "role": "parent"
  }'

# register a child 
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Child",
    "email": "child@example.com",
    "password": "childpass",
    "role": "child",
    "parent_id": 1
  }'

# login a parent
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "parent@example.com",
    "password": "testpass"
  }'

# login as child
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "child@example.com",
    "password": "childpass"
  }'

# get tasks 
curl -X GET http://localhost:8080/tasks \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDg0NzE4NTcsInJvbGUiOiJwYXJlbnQiLCJ1c2VyX2lkIjoxfQ.E2E8SzqrIQeN2MmRZkm0Y5HeImtkcKXEuStrL2yZ-T8"

```
