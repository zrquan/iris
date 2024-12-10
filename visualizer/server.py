import http.server
import socketserver
import argparse
import io
import os
import cgi
import json

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=8194)
args = parser.parse_args()

port = args.port

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        r, info = self.deal_post_data()
        print(r, info, "by: ", self.client_address)
        f = io.BytesIO()
        if r:
            f.write(b"Success\n")
        else:
            f.write(b"Failed\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def deal_post_data(self):
        ctype, pdict = cgi.parse_header(self.headers['Content-Type'])
        if self.path == "/save-result":
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD':'POST', 'CONTENT_TYPE':self.headers['Content-Type'], })
            if form.getvalue("db_name") is None:
                return (False, "Do not have `db_name` field")
            db_name = form.getvalue("db_name")
            obj = []
            for key in form:
                if key == "db_name": continue
                parts = key.split("[")
                idx = int(parts[1][:parts[1].index("]")])
                field = parts[2][:parts[2].index("]")]
                if idx >= len(obj):
                    for i in range(len(obj), idx + 1):
                        obj.append({})
                if field == "is_true_pos":
                    val = form.getvalue(key) == "true"
                elif field == "is_false_pos":
                    val = form.getvalue(key) == "true"
                elif field == "alert_id":
                    val = int(form.getvalue(key))
                elif field == "code_flow_id":
                    val = int(form.getvalue(key))
                else:
                    return (False, f"Unavailable field {field}")
                obj[idx][field] = val
            if "/" in db_name or "\\" in db_name or ".." in db_name:
                return (False, f"Invalid project name {db_name}")
            if not os.path.exists(f"codeql/outputs/{db_name}"):
                return (False, f"Non-existed project {db_name}")
            os.makedirs(f"codeql/outputs/{db_name}/manual", exist_ok=True)
            print(f"Saving to {db_name}:")
            print(obj)
            json.dump(obj, open(f"codeql/outputs/{db_name}/manual/results.json", "w"))
            return (True, "Files uploaded")
        else:
            return (False, f"Unknown path {self.path}")

httpd = socketserver.TCPServer(("", port), CustomHTTPRequestHandler)
print("serving at port", port)
httpd.serve_forever()
