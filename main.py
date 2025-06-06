from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
import ssl
import socket
from datetime import datetime
import OpenSSL.SSL

app = FastAPI()

def get_certificate_expiry(hostname):
    try:
        # Remove any 'https://' or 'http://' from the hostname
        hostname = hostname.replace('https://', '').replace('http://', '').split('/')[0]
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return {
                    "domain": hostname,
                    "expiry_date": expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
                    "days_remaining": (expiry_date - datetime.now()).days
                }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error checking certificate: {str(e)}")

@app.get("/aawash")
async def read_index():
    return FileResponse('index.html')

@app.get("/check-ssl/{domain}")
async def check_ssl(domain: str):
    result = get_certificate_expiry(domain)
    return JSONResponse(content=result)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)