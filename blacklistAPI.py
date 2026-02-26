from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import os
from time import time, strftime, localtime
from datetime import datetime
from json import load, dump
from apscheduler.schedulers.background import BackgroundScheduler
load_dotenv()

API_KEY = os.getenv("FAST_API_KEY")

class IP(BaseModel):
    IP: str
    KEY: str

app = FastAPI()

pending_ips = []
scheduler_initialized = False

def Log(string):
    timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime(datetime.now().timestamp()))
    with open('generator.log', 'a') as file:
        file.write(f"{timestamp} {string}\n")

#this is the only function that was written by AI since I am now sick of this project and frustrated that I need to create temporary ban functionality
def process_api_ban(ip):
    """
    Queue and process an API-added IP ban, and update 72hours.json on schedule.
    """
    global scheduler_initialized

    def update_ip_abuse_score(target_ip):
        with open('72hours.json', 'r') as f:
            data = load(f)

        found = False
        for obj in data:
            if obj.get("IP") == target_ip:
                obj["Abuse Score"] = 35
                Log(f"successfully updated abuse score of {target_ip} so that it gets added to blacklist")
                found = True
                break

        if not found:
            data.append({
                "Timestamp": datetime.now().isoformat(),
                "IP": target_ip,
                "Location": "",
                "Latitude": "",
                "Longitude": "",
                "Number of attacks": 0,
                "Average Threat-Level": 0,
                "Abuse Score": 35,
                "Action": "",
                "Samples": {}
            })
            Log(f"successfully updated abuse score of {target_ip} so that it gets added to blacklist")

        with open('72hours.json', 'w') as f:
            dump(data, f, indent=1)

    if not scheduler_initialized:
        def flush_ips():
            global pending_ips
            for queued_ip in pending_ips[:]:
                update_ip_abuse_score(queued_ip)
            pending_ips.clear()
        
        scheduler = BackgroundScheduler()
        scheduler.add_job(flush_ips, 'cron', minute='10,25,40,55')
        scheduler.start()
        scheduler_initialized = True
    
    # Queue the IP
    if ip not in pending_ips:
        pending_ips.append(ip)

@app.on_event("startup")
async def startup():
    pass

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

    process_api_ban(IP.IP)

    with open('blacklist.txt', 'a') as blacklist:
        blacklist.write(string)

    return f"IP: {IP.IP} added successfully"
    
