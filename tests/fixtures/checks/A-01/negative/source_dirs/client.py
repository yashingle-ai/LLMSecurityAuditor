import os

api_key = os.environ["ACME_API_KEY"]
headers = {"Authorization": f"Bearer {api_key}"}
SECRET_KEY = settings.SECRET_KEY
