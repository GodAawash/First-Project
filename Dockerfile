FROM python:3.9-slim

WORKDIR /app

COPY . .

RUN pip install -r requirements.txt

EXPOSE 9000

# Use uvicorn directly with explicit host and port
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9000"] 