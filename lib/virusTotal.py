import requests
import os 

virusTotalBase = "https://www.virustotal.com/vtapi/v2/"
vtFileReport = "file/report"
vtAPIKey = os.environ.get('VTAPIKey')

def queryVirusTotal(hash):
	params = {
	'apikey': vtAPIKey,
	'resource': hash
	}
	url = virusTotalBase + vtFileReport 
	try:
		r = requests.get(virusTotalBase + vtFileReport, params=params)
		return r.json()

	except requests.exceptions.RequestException as e:
		raise SystemExit(e)
		return 0