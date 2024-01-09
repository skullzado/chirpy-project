# chirpy-project

Guided project for Boot.dev Web Servers course

## What did I learn?

- Build a simple API using Go.
- Handling headers (CORS, etc.)
- Handling static files and serving it
- Use a "database" to persist data

  > **NOTE:** A JSON file is used as a database to store Users and Chirps (tweets)

- Using chi library for building manageable REST API
- Simple authentication:
  - Using ID (email) and password
  - Using Bcrypt library to hashed password and store in the database
  - Using JWT library for further authentication
- Simple authorization:
  - Preventing users from updating or deleting chirps that's not their own
- Handling webhooks
