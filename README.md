# selinux-rc
SELinux/golang remote control server
## What is this?
This is a HTTPS REST API server for controlling your SELinux environment
It uses client certs for authentication
## What can it do?
- Switch between enforcing and permissive modes
- Change any booleans
- Do a restorecon, including recursive
- ... to be continued
## Why should I use it
- You can save access if SELinux is enforcing and something goes wrong
- You can give and opportunity to devops/developers to temporary disable SELinux for tests or in case of emergency
- Add something by yourself :)
## How to run it?
- You must have libselinux installed on your system
- You must set GOPATH and GOBIN environment variables
- Just type go get github.com/kreon/selinux-rc
- Generate ca, server and client certs via openssl or similar way.
 You can take example keys from example/pki/
- Run it via $GOBIN/selinux-rc 8443 ca.crt server.crt server.key
- ...
- Enjoy
## Requests examples
### Get info
```bash
curl -k --cert client.crt --key client.key "https://localhost:8443/info"
```
```json
{
    "mode":"permissive",
    "type":"minimum",
    "version":28
}
```
### Get booleans
```bash
curl -k --cert client.crt --key client.key -X POST "https://localhost:8443/booleans"
```
```json
{"booleans":[
    {"name":"auditadm_exec_content","enabled":true},
    {"name":"authlogin_nsswitch_use_ldap","enabled":true},
    {"name":"authlogin_radius","enabled":false},
    {"name":"authlogin_yubikey","enabled":true},
    {"name":"cron_can_relabel","enabled":false}]
}
```
### Enable boolean
```bash
curl -k --cert client.crt --key client.key -X PUT "https://localhost:8443/enable/staff_use_svirt"
```
```json
{
    "status":"ok",
    "error":""
}
```
### Disable boolean
```bash
curl -k --cert client.crt --key client.key -X PUT "https://localhost:8443/disable/staff_use_svirt"
```
```json
{
    "status":"ok",
    "error":""
}
```
### Switch to enforcing
```bash
curl -k --cert client.crt --key client.key -X PUT "https://localhost:8443/setenforce/1
```
```json
{
    "status":"ok",
    "error":""
}
```
### Switch to permissive
```bash
curl -k --cert client.crt --key client.key -X PUT "https://localhost:8443/setenforce/0"
```
```json
{
    "status":"ok",
    "error":""
}
```
### Do a restorecon
```bash
curl -k --cert client.crt --key client.key -X POST "https://localhost:8443/restorecon/root/123?recursive=true"
```
```json
{
    "status":"ok",
    "error":""
}
```
