from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
import ssl
import socket
import whois
from datetime import datetime, timezone
import os

app = FastAPI()


def get_domain_info(hostname):
    try:
        # Clean the hostname
        hostname = hostname.replace('https://', '').replace('http://', '').split('/')[0]

        # Perform WHOIS query
        domain_info = whois.whois(hostname)

        # Get expiration date
        expiry_date = domain_info.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]

        # Get creation and updated dates
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        updated_date = domain_info.updated_date
        if isinstance(updated_date, list):
            updated_date = updated_date[0]

        if expiry_date:
            # Ensure timezone awareness
            if not expiry_date.tzinfo:
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)

            current_time = datetime.now(timezone.utc)
            days_remaining = (expiry_date - current_time).days

            return {
                "domain_name": hostname,
                "registrar": domain_info.registrar or "Not available",
                "domain_expiry_date": expiry_date.strftime('%Y-%m-%d'),
                "domain_days_remaining": days_remaining,
                "creation_date": creation_date.strftime('%Y-%m-%d') if isinstance(creation_date, datetime) else str(creation_date),
                "updated_date": updated_date.strftime('%Y-%m-%d') if isinstance(updated_date, datetime) else str(updated_date)
            }

        # WHOIS info is incomplete
        return {
            "domain_name": hostname,
            "registrar": "Not available",
            "domain_expiry_date": "Not available",
            "domain_days_remaining": None,
            "creation_date": "Not available",
            "updated_date": "Not available"
        }

    except Exception as e:
        return {
            "domain_name": hostname,
            "registrar": "Not available",
            "domain_expiry_date": "Not available",
            "domain_days_remaining": None,
            "creation_date": "Not available",
            "updated_date": "Not available"
        }


def get_certificate_expiry(hostname):
    try:
        hostname = hostname.replace('https://', '').replace('http://', '').split('/')[0]

        # Get domain info
        domain_info = get_domain_info(hostname)

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    current_time = datetime.now(timezone.utc)
                    days_remaining = (expiry_date - current_time).days

                    return {
                        "domain": hostname,
                        "ssl_expiry_date": expiry_date.strftime('%Y-%m-%d'),
                        "ssl_days_remaining": days_remaining,
                        "domain_expiry_date": domain_info["domain_expiry_date"],
                        "domain_days_remaining": domain_info["domain_days_remaining"],
                        "registrar": domain_info["registrar"],
                        "creation_date": domain_info["creation_date"],
                        "updated_date": domain_info["updated_date"]
                    }

        except (socket.gaierror, ssl.SSLError, ConnectionRefusedError, OSError):
            return {
                "domain": hostname,
                "ssl_expiry_date": "Not available",
                "ssl_days_remaining": "Not available",
                "domain_expiry_date": domain_info["domain_expiry_date"],
                "domain_days_remaining": domain_info["domain_days_remaining"],
                "registrar": domain_info["registrar"],
                "creation_date": domain_info["creation_date"],
                "updated_date": domain_info["updated_date"]
            }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error checking domain: {str(e)}")


@app.get("/")
async def read_root():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return HTMLResponse("<h1>index.html not found</h1>", status_code=404)


@app.get("/check-ssl/{domain}")
async def check_ssl(domain: str):
    result = get_certificate_expiry(domain)
    return JSONResponse(content=result)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
