import time, urllib.request, json

time.sleep(0)  # server already running

data = json.dumps({"prompt": "What is the weather today?"}).encode()
req = urllib.request.Request(
    "http://localhost:8081/api/analyze",
    data=data,
    headers={"Content-Type": "application/json"},
    method="POST",
)

for i in range(5):
    t0 = time.perf_counter()
    with urllib.request.urlopen(req) as r:
        body = json.loads(r.read())
    ms = (time.perf_counter() - t0) * 1000
    print(f"Request {i+1}: {ms:.0f}ms  {body['classification']}")
