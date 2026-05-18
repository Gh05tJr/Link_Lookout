from dotenv import load_dotenv
from os import getenv
import vt
from datetime import datetime 

Red="\033[38;5;197m"
Green="\033[38;5;47m"
Yellow="\033[38;5;11m"
Cyan="\033[38;5;44m"
White="\033[0;37m"
Orange="\033[38;5;215m"
Orange_Light="\x1b[38;5;222m"
NC="\033[00m"

Ask  =     f"{Cyan}[{White}?{Cyan}] {Cyan}"
Success = f"{Green}[{White}√{Green}] {Green}"
Error  =    f"{Red}[{White}!{Red}] {Red}"
Warning  =    f"{Red}[{White}x{Red}] {Red}"
Info  =   f"{Orange}[{White}+{Orange}] {Orange}"
Info_2  =   f"{Orange_Light}[{White}•{Orange_Light}] {Orange_Light}"

Version="1.0"

Logo = fr"""
{Red}  _     _       _      _                _               _
{Red} | |   (_)_ __ | | __ | |    ___   ___ | | _____  _   _| |_
{Red} | |   | | '_ \| |/ / | |   / _ \ / _ \| |/ / _ \| | | | __|
{Red} | |___| | | | |   <  | |__| (_) | (_) |   < (_) | |_| | |_
{Red} |_____|_|_| |_|_|\_\ |_____\___/ \___/|_|\_\___/ \__,_|\__|
{" "*33}{Green}Operation: Scanning Horizon{Orange}
{Orange}{" "*54}[{Yellow}v{Version}{Orange}]
{Orange}{" "*48}""" + f"[{Yellow}By {Green}\x47\x68\x30\x35\x74\x4a\x72{Orange}]" + fr"""
"""

def Format_Date(timestamp):
    if timestamp:
        return datetime.fromtimestamp(int(timestamp)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    return "N/A"

print(Logo)
load_dotenv()

API_Key = getenv('API_Key')

if API_Key == None:
    print(f"{Error}API Key Not Found (Create a '.env' File And Add Your API Key as 'API_Key' In The Same Folder As the Program).{NC}")

else:
    URL = input(f"{Ask}URL Input:- ")

    if URL == "":
        print(f"{Error}Empty Input")

    elif URL.isdigit() == True:
        print(f"{Error}Numeric Input")

    else:    
        try:
            with vt.Client(apikey = API_Key) as Client:
                print(Info+"Scanning... please wait...")
                Analysis = Client.scan_url(url = URL,wait_for_completion = True )
                Stats = Analysis.stats
                URL_ID = vt.url_id(URL)
                URL_Obj = Client.get_object("/urls/{}", URL_ID)

                Raw_Response = Client.get_json(f"/urls/{URL_ID}", params={"relationships": "last_serving_ip_address"})
                IP_Data = Raw_Response.get("data", {}).get("relationships", {}).get("last_serving_ip_address", {}).get("data")
                
                Redirect_Chain = URL_Obj.get('redirection_chain', [])
                
                Results = URL_Obj.last_analysis_results
                
                Malicious_Engines = [Name for Name, info in Results.items() if info['result'] == 'malicious']
                Suspicious_Engines = [Name for Name, info in Results.items() if info['result'] == 'suspicious']
                Phishing_Engines = [Name for Name, info in Results.items() if info['result'] == 'phishing']
                Spam_Engines = [Name for Name, info in Results.items() if info['result'] == 'spam']
                Clean_Engines = [Name for Name, info in Results.items() if info['result'] == 'clean']
                Unrated_Engines = [Name for Name, info in Results.items() if info['result'] == 'unrated']
                
                print(f"\n{Info_2}Page Title:- {URL_Obj.get('title') or 'N/A'}")
                print(f"\n{Info_2}Original URL:- {URL_Obj.get('url')}")
                print(f"\n{Info_2}Final Redirected URL:- {URL_Obj.get('last_final_url') or 'N/A'}")
                print(f"\n{Info_2}Serving IP:- {IP_Data["id"] if IP_Data else "N/A"}")

                if Redirect_Chain:
                    print(f"\n{Info_2}Detected Redirection Chain ({len(Redirect_Chain)} Hops):-")
                    for Index, Hop_URL in enumerate(Redirect_Chain, start=1):
                        if Index == len(Redirect_Chain):
                            print(f"    └── {Green}[Final Destination]{NC} {Hop_URL}")
                        else:
                            print(f"    ├── [{Index}] {Hop_URL}")
                else:
                    print(f"\n{Info_2}No Redirection Chain Present (Direct Connection).")

                print(f"\n{Info}{len(Clean_Engines)} Vendors Marked The URL as Clean.")
                
                if Malicious_Engines:
                    print(f"\n{Warning}Flagged as Malicious By {len(Malicious_Engines)} Vendors: {', '.join(Malicious_Engines)}")
                else:
                    print(f"\n{Info}No Vendors Flagged This URL as Malicious.")
                
                if Suspicious_Engines:
                    print(f"\n{Warning}Flagged as Suspicious By {len(Suspicious_Engines)} Vendors: {', '.join(Suspicious_Engines)}")
                else:
                    print(f"\n{Info}No Vendors Flagged This URL as Suspicious.")

                if Phishing_Engines:
                    print(f"\n{Warning}Flagged as Phishing by {len(Phishing_Engines)} Vendors: {', '.join(Phishing_Engines)}")
                else:
                    print(f"\n{Info}No Vendors Flagged This URL as Phishing.")
                
                if Spam_Engines:
                    print(f"\n{Warning}Flagged as Spam by {len(Spam_Engines)} Vendors: {', '.join(Spam_Engines)}")
                else:
                    print(f"\n{Info}No Vendors Flagged This URL as Spam.")

                print(f"\n{Info}{len(Unrated_Engines)} Vendors Marked The URL as Unrated.\n")

                Categories = URL_Obj.get('categories', {})
                print(f"{Info_2}Categorization Of The URL By Vendors:- ")
                for k in Categories:
                    print(f"{Info}{k} : {Categories[k]}")

                print(f"\n{Info_2}History & Tracking Timestamps Of The URL:- ")
                print(f"{Info}First Submission Date:- {Format_Date(URL_Obj.get('first_submission_date'))}")
                print(f"{Info}Last Submission Date:- {Format_Date(URL_Obj.get('last_submission_date'))}")
                print(f"{Info}Last Analysis Date:- {Format_Date(URL_Obj.get('last_analysis_date'))}")
                print(f"{Info}Times Submitted:- {URL_Obj.get('times_submitted')}")
                
                print(NC)
                Client.close()

        except:
            print(f"{Error}Check The Entered URL(Wrong Data Entered)+{NC}")
            Client.close()