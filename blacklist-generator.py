import requests
import json
from json import dump, load
from datetime import datetime, timedelta
import os 
from time import strftime, localtime, time
import time
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("ABUSEDB_API_KEY")

QUERY = r"""
{host="lsreverseproxy"}
| json log
| __error__=""
| line_format "{{.log}}"
| json source_ip="eventData.sourceIP"
| __error__=""
| source_ip != ip("10.0.0.0/8")
| json
""".strip()

MINUTES = 15

base = os.getenv("LOKI_ENDPOINT")
params = {
    "query": QUERY,
    "start": str(int((time.time() - 60*MINUTES) * 1_000_000_000)),
    "end":   str(int(time.time() * 1_000_000_000)),
    "limit": "400",
}

# Turn raw logs into usable "streams"
r = requests.get(f"{base}/loki/api/v1/query_range", params=params)
result = r.json()
data = (result["data"])
streams = data["result"]

def Log(string):
    timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime(datetime.now().timestamp()))
    with open('generator.log', 'a') as file:
        file.write(f"{timestamp} {string}\n")

def getIP(stream):
    actualStream = stream["stream"]
    # values = stream["values"][0]
    # jsonValues = json.loads(values[1])
    if actualStream.get("eventData_sourceIP") == None:
        return False
    else:
        return actualStream.get("eventData_sourceIP") 

def getSample(stream):
    actualStream = stream["stream"]
    # values = stream["values"][0]
    # jsonValues = json.loads(values[1])
    return actualStream["eventData_matchedSample"]

def getTL(stream):
    actualStream = stream["stream"]
    # values = stream["values"][0]
    # jsonValues = json.loads(values[1])
    return actualStream["eventData_waapCalculatedThreatLevel"]

def getTarget(stream):
    actualStream = stream["stream"]
    return actualStream["eventData_httpHostName"]

def getAction(stream):
    actualStream = stream["stream"]
    # values = stream["values"][0]
    # jsonValues = json.loads(values[1])
    return actualStream["eventData_securityAction"]

def getTimestamp(stream):
    actualStream = stream["stream"]
    timestamp = actualStream["eventTime"]
    time = datetime.fromisoformat(timestamp)
    realtime = time - timedelta(hours=7) # change value to subtract timezone from UTC
    return realtime

def fetchIPreputation(ip):
    '''
    Returns API that looks like this
    {'data': 
        {'ipAddress': '198.60.19.58', 
        'isPublic': True, 
        'ipVersion': 4, 
        'isWhitelisted': None, 
        'abuseConfidenceScore': 0, 
        'countryCode': 'US', 
        'usageType': 'University/College/School', 
        'isp': 'Brigham Young University', 
        'domain': 'byu.edu', 
        'hostnames': [], 
        'isTor': False, 
        'totalReports': 0, 
        'numDistinctUsers': 0, 
        'lastReportedAt': None}
        }
    '''
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    decodedResponse = json.loads(response.text)
    return decodedResponse
    #return json.dumps(decodedResponse, sort_keys=True, indent=4)

def addTo72HourBlacklist(ip):
    if not isIn72HourBlacklist(ip):
        Log(f"Adding {ip} to blacklist")
    with open('72hourban.txt', 'a') as IPblacklist:
        IP = f"{ip}\n"
        IPblacklist.write(IP)

def isIn72HourBlacklist(ip):
    with open('72hourban.txt', 'r') as blacklist:
        ips = blacklist.readlines()
        if ip + '\n' in ips:
            return True
        else:
            return False       

def GetAbuseScore(reputation):    
    badScore = reputation['data']['abuseConfidenceScore']
    ip = reputation['data']['ipAddress']
    return ip, badScore 

def getLocation(IP):
    '''
    Queries IP data from ip-data API below are all the keys 
    {
        "query": "128.187.112.28",
        "status": "success",
        "continent": "North America",
        "continentCode": "NA",
        "country": "United States",
        "countryCode": "US",
        "region": "UT",
        "regionName": "Utah",
        "city": "Provo",
        "district": "",
        "zip": "84602",
        "lat": 40.3598,
        "lon": -111.7304,
        "timezone": "America/Denver",
        "offset": -25200,
        "currency": "USD",
        "isp": "Brigham Young University",
        "org": "Brigham Young University",
        "as": "AS6510 Brigham Young University",
        "asname": "BYU",
        "mobile": false,
        "proxy": false,
        "hosting": false
    }
    '''
    locationData = requests.get(f"http://ip-api.com/json/{IP}").json()
    City = locationData["city"]
    Country = locationData["country"]
    Region = locationData["regionName"]
    Latitude = locationData["lat"]
    Longitude = locationData["lon"]
    return {"City" : City, "Region" : Region, "Country" : Country, "Latitude": Latitude, "Longitude": Longitude}

Log(f"{len(streams)} total logs returned by query")

# Below we start converting logs in to Attacker Class objecs
Attackers = []

class Attacker:
    def __init__(self, IP, Location, Samples, ThreatLevel, AbuseScore, Action, Timestamp):
        self.IP = IP
        self.Location = dict(Location)
        self.Samples = dict(Samples)
        self.ThreatLevel = list(ThreatLevel)
        self.AbuseScore = AbuseScore
        self.Action = Action
        self.Timestamp = str(Timestamp)

    def AverageThreatLevel(self):
        totalscore = 0
        for i in self.ThreatLevel:
            totalscore += int(i) 
        return totalscore / len(self.ThreatLevel)
    
    def AttackNumber(self):
        totalAttacks = 0
        for i in self.Samples:
            totalAttacks += len(self.Samples[i])
        return totalAttacks

    def __str__(self):
        AvgTL = self.AverageThreatLevel()
        
        totalAttackNum = self.AttackNumber()

        samples = ""
        for i in self.Samples:
            samples += f"\n {str(i)}"

        return f"{self.Timestamp}\nIP: {self.IP}\nLocation: {self.Location["City"]}, {self.Location["Region"]}, {self.Location["Country"]}\nCoordinates: {self.Location["Latitude"]}, {self.Location["Longitude"]}\nNumber of attacks: {totalAttackNum}\nAverage Threat-Level: {AvgTL}\nAbuse Score: {self.AbuseScore}\nAction: {self.Action}"

    ## did not self code this method because im lazy
    def to_dict(self):
        AvgTL = self.AverageThreatLevel()
        city = self.Location.get("City", "")
        region = self.Location.get("Region", "")
        country = self.Location.get("Country", "")
        lat = self.Location.get("Latitude")
        lon = self.Location.get("Longitude")
        totalAttackNum = self.AttackNumber()

        location_str = ", ".join(part for part in (city, region, country) if part)

        obj = {"Timestamp": self.Timestamp,"IP": self.IP,"Location": location_str,"Latitude": lat, "Longitude": lon,"Number of attacks": totalAttackNum,"Average Threat-Level": AvgTL,"Abuse Score": self.AbuseScore,"Action": self.Action,"Samples": self.Samples,}
        return obj
    
uniqueIPs = []
# Get unique IPs from the queried Logs
for i in range(len(streams)):    
    IP = getIP(streams[i])
    if IP == False:
        continue
    if IP not in uniqueIPs:
        uniqueIPs.append(IP)
        reputation = fetchIPreputation(IP)
        IP, AbuseScore = GetAbuseScore(reputation)
        # Create unique Attacker object
        Attackers.append(Attacker(IP,getLocation(IP),{},[],AbuseScore,getAction(streams[i]),getTimestamp(streams[i])))

Log(f"{len(uniqueIPs)} unique IPs present in logs")

for x in range(len(Attackers)):
    uniqueTargets = []
    for i in range(len(streams)):
        IP = getIP(streams[i])
        if Attackers[x].IP == IP:
            Target = getTarget(streams[i])
            if Target not in uniqueTargets:
                uniqueTargets.append(Target)
                Attackers[x].Samples[Target] = []

            sample = getSample(streams[i])
            Attackers[x].Samples[Target].append(sample)
            TL = getTL(streams[i])
            Attackers[x].ThreatLevel.append(TL)

# check if IP is already in blacklist
for IP in uniqueIPs:        
    if isIn72HourBlacklist(str(IP)) == True:
        Log(f"ALERT: Traffic detected from IP: {IP} that should be blocked!")
        uniqueIPs.remove(IP)

# print cleanly to stdout, will only print first 50 chars for each sample
def cleanPrint():
    for i in range(len(Attackers)):
        print(f"{Attackers[i]}")
        for x in Attackers[i].Samples.keys():
            print(f"Target Host: {x}")
            for y in range(len(Attackers[i].Samples[x])):
                #print(f"Target host: {Attackers[i].Samples}")
                string = Attackers[i].Samples[x][y]
                print(f"{string[:50]}")
        print('\n')

def ConvertToJSON(jsonFile, Attackers):
    objs = []

    if '24' in jsonFile:
        delta = 24
    else:
        delta = 72

    with open(jsonFile, 'r') as file:
        check = os.stat(jsonFile).st_size
        if check:
            objs = load(file)
            
    now = datetime.now()
    yesterday = now - timedelta(hours=delta)

    newObjs = []

    for i in range(len(Attackers)):
        Attacker = Attackers[i]
        jsonObj = Attacker.to_dict()
        newObjs.append(jsonObj)

    for obj in objs:
        timestamp = datetime.fromisoformat(obj["Timestamp"])
        if timestamp > yesterday :
            newObjs.append(obj)

    with open(jsonFile, 'w') as file:
        dump(newObjs, file, indent=1)


def determineIfEvil(Attacker):

    Region = Attacker["Location"].split(',', 2)[1]
    Country = Attacker["Location"].rsplit(',', 1)[1]

    IP = Attacker["IP"]
    # if isInBlacklist(IP):
    #     return False
    if Attacker["Abuse Score"] >= 35:
        return True
    if Attacker["Abuse Score"] >= 20 and (Region != " Utah" or "Utah"):
        return True
    if Attacker["Abuse Score"] >= 5 and (Country != "United States" or " United States"):
        return True
    else:
        return False

def generateBlacklist(jsonFile):
    Attackers = []
    uniqueBadIPs = []
    needsHuman = []
    
    with open(jsonFile, 'r') as file:
        check = os.stat(jsonFile).st_size
        if check:
            Attackers = load(file)
    
    with open('72hourban.txt','w') as banFile:
        pass

    for Attacker in Attackers:
        if determineIfEvil(Attacker) and Attacker["IP"] not in uniqueBadIPs:
            addTo72HourBlacklist(Attacker["IP"])
            uniqueBadIPs.append(Attacker["IP"])
        elif Attacker["IP"] not in uniqueBadIPs:
            needsHuman.append(Attacker)
            uniqueBadIPs.append(Attacker["IP"])

    with open('needsHuman.json', 'w') as file:
        dump(needsHuman, file, indent=1)
    
    with open('threatlist.txt', 'r') as badList:
        badlist = badList.readlines()

    with open('72hourban.txt', 'r') as blacklist:
        badIPs = blacklist.readlines()

    with open('blacklist.txt', 'w') as black:
        black.writelines(badlist)
        black.writelines("\n\n# Below are our own blacklisted IPs\n")
        black.writelines(badIPs)

ConvertToJSON('24hours.json', Attackers)
ConvertToJSON('72hours.json', Attackers)

generateBlacklist('72hours.json')

