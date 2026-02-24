from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import os
load_dotenv()

API_KEY = os.getenv("FAST_API_KEY")

class IP(BaseModel):
    IP: str
    KEY: str

app = FastAPI()
@app.get("/")
async def root():
    return "message POST bad IPs to /addip using {'IP':'1.1.1.1', 'KEY':'KEY'}"

@app.post("/addip")
async def addIP(IP: IP):

    if IP.KEY != API_KEY:
        return HTTPException(status_code=403,detail="Not Authorized")
    
    string = f"{IP.IP}\n"

    with open('72hourban.txt', 'r') as blacklist:
        ips = blacklist.readlines()
        if string in ips:
            return HTTPException(status_code=409,detail="IP is already in blacklist")
   
    with open('72hourban.txt', 'a') as IPblacklist:
        IPblacklist.write(string)

    with open('blacklist.txt', 'a') as blacklist:
        blacklist.write(string)

    return f"IP: {IP.IP} added successfully"
    