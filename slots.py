from email.mime import base
import os,requests
import utils
from dotenv import load_dotenv
load_dotenv()
BASE=os.getenv("SLOT_API_URL","")
TOTAL_SLOTS=int(os.getenv("TOTAL_SLOTS","2225"))
CHUNK_SIZE=int(os.getenv("CHUNK_SIZE","1000000000000")) 
TOTAL_WORK=int(os.getenv("TOTAL_WORK",str(TOTAL_SLOTS*CHUNK_SIZE)))
HEAD={"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0"}

def pick_slot():    
    global BASE
    j={}
    if(BASE != ""):
        try:
            r=requests.get(f"{BASE}/api/slot",params={"total":TOTAL_SLOTS,"prefer_active":"1"},timeout=10); r.raise_for_status()
            j=r.json()
        except e:   
            utils.log("error",e)
        
    return j

def upsert_slot(job_id,**fields):
    global BASE
    j={}
    if(BASE != ""):
        try:
            r=requests.post(f"{BASE}/api/slot/upsert",json={"job_id":int(job_id),**fields},headers=HEAD,timeout=10); r.raise_for_status()
            j=r.json()
        except e:
            utils.log("error", e)
        
    return j


