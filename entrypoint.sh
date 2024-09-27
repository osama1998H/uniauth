#!/bin/bash
# entrypoint.sh

# Exit immediately if a command exits with a non-zero status
set -e

echo "Environment Variables:"
echo "POSTGRES_SERVER: $POSTGRES_SERVER"
echo "POSTGRES_USER: $POSTGRES_USER"
echo "POSTGRES_PASSWORD: $POSTGRES_PASSWORD"
echo "POSTGRES_DB: $POSTGRES_DB"

# Wait for the database to be ready
echo "Waiting for the database to be ready..."
while ! nc -z $POSTGRES_SERVER 5432; do
  sleep 0.1
done
echo "Database is ready!"

# Run migrations
echo "Running database migrations..."
# alembic upgrade head || { echo "Alembic migrations failed"; exit 1; }

# Start the application
echo "Starting the application..."
exec "$@"
