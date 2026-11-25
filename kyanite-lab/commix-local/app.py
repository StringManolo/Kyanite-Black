from flask import Flask, request, Response
import subprocess

app = Flask(__name__)

@app.get("/")
def index():
    host = request.args.get("host", "127.0.0.1")

    # INTENTIONALLY VULNERABLE: this lab concatenates user input into a shell command.
    # It is for local, isolated training only. Never deploy this service publicly.
    command = f"printf 'Host: '; echo {host}"

    try:
        completed = subprocess.run(
            command,
            shell=True,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
        output = completed.stdout + completed.stderr
        status = 200
    except subprocess.TimeoutExpired:
        output = "Command timed out"
        status = 504

    return Response(output, status=status, content_type="text/plain; charset=utf-8")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
