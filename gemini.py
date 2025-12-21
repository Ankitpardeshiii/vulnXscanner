from flask import Flask, render_template_string, request, jsonify
import socket
import threading
import queue
import google.generativeai as genai
from dotenv import load_dotenv
import os



# ---------------- FLASK INIT ----------------
app = Flask(__name__)

# ---------------- SCANNER LOGIC ----------------
common_ports = [21,22,23,25,53,80,110,135,137,138,139,143,161,389,443,445,3306,3389,5432,5900,8080,8443,9200]
port_services = {80:"HTTP",443:"HTTPS",22:"SSH",21:"FTP",23:"TELNET",445:"SMB",3389:"RDP"}

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        try:
            banner = s.recv(1024).decode(errors="ignore").strip()
        except:
            banner = "No banner"
        s.close()
        return banner
    except:
        return "No banner"

def scan_target(ip):
    results = []
    for port in common_ports:
        try:
            s = socket.socket()
            s.settimeout(0.6)
            if s.connect_ex((ip, port)) == 0:
                banner = grab_banner(ip, port)
                service = port_services.get(port, "Unknown")
                results.append((port, service, banner))
            s.close()
        except:
            pass
    return results

def resolve_target(target):
    target = target.replace("http://","").replace("https://","").split("/")[0]
    try:
        ip = socket.gethostbyname(target)
        return ip
    except:
        return None

# ---------------- MAIN UI TEMPLATE ----------------
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>VulnX</title>
<style>
body{background:#0a0c10;color:white;font-family:Arial;}
.card{background:#12151c;border:1px solid #232833;border-radius:10px;padding:20px;cursor:pointer;margin:10px;}
.card:hover{transform:scale(1.04);}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;}
.box{background:#12151c;padding:20px;border-radius:10px;width:600px;max-height:80vh;overflow:auto;}
</style>
</head>
<body>

<h1 style="text-align:center;color:#10b981;">VulnX Security Scanner</h1>
<br>

<form method="post">
<input type="text" name="target" placeholder="scanme.nmap.org" required style="width:300px;padding:10px;">
<button style="padding:10px;">SCAN</button>
</form>

{% if results %}
<h2>Results:</h2>
{% for port,service,banner in results %}
<div class="card" onclick="askAI({{port}}, '{{service}}', `{{banner}}`)">
<b>Port:</b> {{port}}<br>
<b>Service:</b> {{service}}<br>
<b>Banner:</b> {{banner}}
</div>
{% endfor %}
{% endif %}

<script>
function askAI(port, service, banner){
fetch("/gemini-ai", {
method:"POST",
headers:{ "Content-Type":"application/json" },
body:JSON.stringify({port, service, banner})
})
.then(r=>r.text())
.then(text => {
let m=document.createElement("div")
m.className="modal"
m.innerHTML = `
<div class="box">
<h2 style="color:#10b981;">Gemini AI Report</h2>
<pre>${text}</pre>
<br>
<button onclick="document.body.removeChild(this.parentNode.parentNode)" style="padding:10px;background:#10b981;border:0;border-radius:5px;cursor:pointer;">Close</button>
</div>
`
document.body.appendChild(m)
})
.catch(err => alert("AI Error: "+err))
}
</script>

</body>
</html>
"""

# ---------------- MAIN ROUTE ----------------
@app.route("/", methods=["GET","POST"])
def home():
    results = None
    if request.method == "POST":
        t = request.form["target"].strip()
        ip = resolve_target(t)
        if ip:
            results = scan_target(ip)
    return render_template_string(HTML, results=results)

# ---------------- GEMINI ROUTE ----------------
@app.route("/gemini-ai", methods=["POST"])
def gemini_ai():
    try:
        data = request.get_json()
        port = data["port"]
        service = data["service"]
        banner = data["banner"]

        prompt = f"""
You are a cybersecurity expert. Analyze:

Port: {port}
Service: {service}
Banner: {banner}

Give:
- risks
- exploit scenario
- recommendations
- CVE notes
- severity score (1-10)
"""

        model = genai.GenerativeModel("gemini-1.5-flash")
        r = model.generate_content([prompt])

        if hasattr(r,"text"):
            return r.text
        else:
            return "No AI output."

    except Exception as e:
        return f"AI Error: {e}", 500


# ---------------- RUN ----------------
if __name__ == "__main__":
    print("🔥 VulnX Ready → http://127.0.0.1:5000")
    app.run(debug=True)
