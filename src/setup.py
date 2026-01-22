import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()  # This will automatically look for a .env file and load the configurations

# Directory settings for datasets and models
data_dir = 'data'
models_dir = 'models'

# Example environment variables (should be in .env file)
ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL')
KAFKA_URL = os.getenv('KAFKA_URL')
REDIS_URL = os.getenv('REDIS_URL')

# Function to log environment setup
def log_setup():
    print(f"Data directory: {data_dir}")
    print(f"Models directory: {models_dir}")
    print(f"Elasticsearch URL: {ELASTICSEARCH_URL}")
    print(f"Kafka URL: {KAFKA_URL}")
    print(f"Redis URL: {REDIS_URL}")

# Perform initial logging of setup
if __name__ == "__main__":
    log_setup()
