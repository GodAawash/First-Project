from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import ssl
import socket
import whois
from datetime import datetime, timezone
import os
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static directory
app.mount("/static", StaticFiles(directory="static"), name="static")


def extract_hostname(url: str) -> str:
    try:
        # If the URL doesn't start with a protocol, add https:// to help urlparse
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        parsed = urlparse(url)
        if not parsed.netloc:
            return url
            
        # Get the hostname and remove 'www.' if present
        hostname = parsed.netloc.lower()
        if hostname.startswith('www.'):
            hostname = hostname[4:]
            
        return hostname
    except Exception:
        # If parsing fails, return the original input
        return url


def get_domain_info(hostname):
    try:
        domain_info = whois.whois(hostname)

        # Handle possible list values
        expiry_date = domain_info.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]

        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        updated_date = domain_info.updated_date
        if isinstance(updated_date, list):
            updated_date = updated_date[0]

        if expiry_date:
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

        return {
            "domain_name": hostname,
            "registrar": "Not available",
            "domain_expiry_date": "Not available",
            "domain_days_remaining": None,
            "creation_date": "Not available",
            "updated_date": "Not available"
        }

    except Exception:
        return {
            "domain_name": hostname,
            "registrar": "Not available",
            "domain_expiry_date": "Not available",
            "domain_days_remaining": None,
            "creation_date": "Not available",
            "updated_date": "Not available"
        }


def get_certificate_expiry(input_url: str):
    try:
        hostname = extract_hostname(input_url)
        domain_info = get_domain_info(hostname)

        try:
            context = ssl._create_unverified_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    expiry_date = cert.not_valid_after.replace(tzinfo=timezone.utc)
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
                "ssl_expiry_date": "Not available (host unreachable or no SSL)",
                "ssl_days_remaining": "N/A",
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
    try:
        return FileResponse("static/index.html")
    except Exception as e:
        return HTMLResponse(f"<h1>Error: {str(e)}</h1>", status_code=404)


@app.get("/check-ssl/{domain}")
async def check_ssl(domain: str):
    result = get_certificate_expiry(domain)
    return JSONResponse(content=result)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
