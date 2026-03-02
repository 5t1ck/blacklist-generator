import requests as r
from dotenv import load_dotenv
import os

load_dotenv()

KEY = os.getenv("FAST_API_KEY")

ENDPOINT = "truepositive"

SAMPLE = ["fawefdagfagsdaf","faaekjfdiojaoif"]

data = {"IP":"1.1.1.1","KEY":KEY,"SAMPLES": SAMPLE,"TL":4.0}

test = r.post(f"http://localhost:8000/{ENDPOINT}", json = data)

print()
print(test.text)