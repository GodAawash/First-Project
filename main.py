from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()

@app.get("/aawash")
async def read_index():
    return FileResponse('index.html')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)