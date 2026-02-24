import requests

r = requests.get("http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt")

threatlist = r.text

with open('threatlist.txt', 'w') as file:
    file.writelines(threatlist)

with open('threatlist.txt', 'r') as badList:
    badlist = badList.readlines()

# Combine blacklist and threatlist

with open('72hourban.txt', 'r') as blacklist:
    badIPs = blacklist.readlines()

with open('blacklist.txt', 'w') as black:
    black.writelines(badlist)
    black.writelines("\n\n# Below are our own blacklisted IPs\n")
    black.writelines(badIPs)

