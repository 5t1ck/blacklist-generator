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

def DebugLog(string):
    timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime(datetime.now().timestamp()))
    with open('debug.txt', 'a') as file:
        file.write(f"{timestamp} [process_api_ban] {string}\n")

#this is the only function that was written by AI since I am now sick of this project and frustrated that I need to create temporary ban functionality
def process_api_ban(ip):
    """
    Queue and process an API-added IP ban, and update 72hours.json on schedule.
    """
    global scheduler_initialized
    DebugLog(
        f"called with ip={ip}. scheduler_initialized={scheduler_initialized}, pending_ips_count={len(pending_ips)}"
    )

    def update_ip_abuse_score(target_ip):
        DebugLog(f"update_ip_abuse_score start for {target_ip}")
        with open('72hours.json', 'r') as f:
            data = load(f)
        DebugLog(f"loaded 72hours.json with {len(data)} records")

        found = False
        for obj in data:
            if obj.get("IP") == target_ip:
                DebugLog(f"found existing record for {target_ip}; setting Abuse Score to 35")
                obj["Abuse Score"] = 35
                obj["Timestamp"] = datetime.now().isoformat()
                Log(f"successfully updated abuse score of {target_ip} so that it gets added to blacklist")
                DebugLog(f"updated existing record for {target_ip}")
                found = True
                break

        if not found:
            DebugLog(f"no existing record for {target_ip}; appending new record with Abuse Score 35")
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
            DebugLog(f"appended new record for {target_ip}")

        with open('72hours.json', 'w') as f:
            dump(data, f, indent=1)
        DebugLog(f"wrote 72hours.json with {len(data)} records after processing {target_ip}")

    if not scheduler_initialized:
        DebugLog("scheduler not initialized; creating BackgroundScheduler")
        def flush_ips():
            global pending_ips
            DebugLog(f"flush_ips triggered; pending_ips_count={len(pending_ips)}")
            for queued_ip in pending_ips[:]:
                DebugLog(f"processing queued ip {queued_ip}")
                update_ip_abuse_score(queued_ip)
            pending_ips.clear()
            DebugLog("flush_ips completed; pending_ips cleared")
        
        scheduler = BackgroundScheduler()
        scheduler.add_job(flush_ips, 'cron', minute='10,25,40,55')
        DebugLog("scheduler job added with cron minute='10,25,40,55'")
        scheduler.start()
        DebugLog("BackgroundScheduler started")
        scheduler_initialized = True
        DebugLog("scheduler_initialized set to True")
    
    # Queue the IP
    if ip not in pending_ips:
        pending_ips.append(ip)
        DebugLog(f"queued ip={ip}; pending_ips_count={len(pending_ips)}")
    else:
        DebugLog(f"ip={ip} already queued; pending_ips_count={len(pending_ips)}")

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

    return f"IP: {IP.IP} added successfully"
    
