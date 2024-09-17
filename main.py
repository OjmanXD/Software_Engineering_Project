import json
import nmap
import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Define Pydantic model for request body
class ScanRequest(BaseModel):
    host: str

class RemarksRequest(BaseModel):
    remarks: str

app = FastAPI()

# Database connection
DATABASE_URL = "dbname='Software_project' user='postgres' host='localhost' password='Three141592653!'"
conn = psycopg2.connect(DATABASE_URL)

# Create table if not exists
with conn.cursor() as cur:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            result JSONB NOT NULL
        )
    """)
    conn.commit()
    
# Create table if not exists
with conn.cursor() as cur:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS remarks (
            scan_id SERIAL PRIMARY KEY,
            remarks TEXT
        )
    """)
    conn.commit()

# Scan ports asynchronously
def scan_ports(target_ip):
    scan_results = {}
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-F')
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            scan_results[host] = {}
            for proto in nm[host].all_protocols():
                scan_results[host][proto] = []
                lport = nm[host][proto].keys()
                for port in lport:
                    port_info = nm[host][proto][port]
                    if port_info['state'] == 'open':
                        service = port_info['name']
                        scan_results[host][proto].append({"port": port, "service": service})
    return json.dumps(scan_results)

# Store scan results in the database
def store_scan_results(scan_results):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO scans (result)
            VALUES (%s)
        """, (Json(scan_results),))
        conn.commit()

# Retrieve scan results and remarks from the database
# Retrieve scan results and remarks from the database
def get_scan_results():
    with conn.cursor() as cur:
        cur.execute("""
            SELECT s.id, s.result, r.remarks 
            FROM scans s 
            LEFT JOIN remarks r ON s.id = r.scan_id
        """)
        rows = cur.fetchall()
        # Convert each row into a dictionary
        results = []
        for row in rows:
            scan_id = row[0]
            result = row[1]
            remarks = row[2] if row[2] else "None"  # If remarks are None, set them to "None"
            result_dict = {"id": scan_id, "result": result, "remarks": remarks}
            results.append(result_dict)
        return results


@app.get("/")
async def root():  
    return {}

# Endpoint to trigger port scan
@app.post("/scan/")
def trigger_scan(request_body: ScanRequest):
    host = request_body.host
    # scan_results = scan_ports(host)
    # store_scan_results(scan_results)
    # return {"message": "Scan completed successfully", "scan_results": json.loads(scan_results)}
    scan_results = scan_ports(host)
    store_scan_results(scan_results)
    return {"message":"Scan completed successfully", "scan_results": json.loads(scan_results)}

# Endpoint to retrieve all scan results
@app.get("/results/")
def get_results():
    return get_scan_results()

# Endpoint to add remarks to a scan
@app.put("/remarks/{scan_id}/")
def add_remarks(scan_id: int, request_body: RemarksRequest):
    remarks = request_body.remarks
    # Insert remarks into the 'remarks' table
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO remarks (scan_id, remarks)
            VALUES (%s, %s)
            ON CONFLICT (scan_id) DO UPDATE
            SET remarks = EXCLUDED.remarks
        """, (scan_id, remarks))
        conn.commit()
    return {"message": f"Remarks added to scan {scan_id}: {remarks}"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
