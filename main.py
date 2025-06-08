from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import ssl
import socket
from datetime import datetime

app = FastAPI()


def get_certificate_expiry(hostname):
    try:
        
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

@app.get("/")
async def read_root():
    return FileResponse('index.html')

@app.get("/check-ssl/{domain}")
async def check_ssl(domain: str):
    result = get_certificate_expiry(domain)
    return JSONResponse(content=result)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)