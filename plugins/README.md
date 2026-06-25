# This directory is mounted into the Kafka Connect container as a plugin volume.
# The MongoDB Kafka Connector JAR is installed here automatically on first startup
# via the `confluent-hub install` command in docker-compose.yml.
#
# You do NOT need to manually add anything here.
# After running `docker compose up`, this folder will be populated with the connector.
