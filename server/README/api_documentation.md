# 消息系统API文档

## 概述
本文档详细说明了消息系统的API接口，包括用户认证、消息发送、接收、权限管理等功能。所有请求都需要在Header中包含有效的认证信息。

## API接口

### 1. 用户注册
**请求URL:** `/register`
**方法:** POST

**请求参数:**
```json
{
    "user_id": "用户ID"
}
```

**响应示例:**
```json
{
    "message": "注册成功",
    "user_id": "user123"
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/register"
headers = {
    "Content-Type": "application/json"
}
data = {
    "user_id": "user123",
    "public_key": "your_public_key"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

### 2. 用户登录
**请求URL:** `/login`
**方法:** POST

**请求参数:**
```json
{
    "user_id": "用户ID"
}
```

**响应示例:**
```json
{
    "message": "登录成功",
    "user_id": "user123"
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/login"
headers = {
    "Content-Type": "application/json"
}
data = {
    "user_id": "user123"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

### 3. 用户登出
**请求URL:** `/logout`
**方法:** POST

**请求参数:**
```json
{
    "user_id": "用户ID"
}
```

**响应示例:**
```json
{
    "message": "登出成功"
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/logout"
headers = {
    "Content-Type": "application/json"
}
data = {
    "user_id": "user123"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

### 4. 发送消息
**请求URL:** `/send`
**方法:** POST

**请求参数:**
```json
{
    "receiver_id": "接收者的用户ID",
    "encrypted_content": "加密后的消息内容"
}
```

**响应示例:**
```json
{
    "message": "Message sent successfully",
    "message_id": 123,
    "timestamp": "2024-01-01T12:00:00"
}
```

**调用示例:**


Python:
```python
import requests

url = "http://localhost:5000/send"
headers = {
    "Authorization": "Bearer your_access_token",
    "Content-Type": "application/json"
}
data = {
    "receiver_id": "user123",
    "encrypted_content": "encrypted_message_content"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

### 2. 获取收件箱消息
**请求URL:** `/inbox`
**方法:** GET

**响应示例:**
```json
{
    "messages": [
        {
            "id": 123,
            "sender_id": "发送者ID",
            "encrypted_content": "加密的消息内容",
            "timestamp": "2024-01-01T12:00:00"
        }
    ]
}
```

**调用示例:**

curl:
```bash
curl -X GET http://localhost:5000/inbox \
  -H "Authorization: Bearer your_access_token"
```

Python:
```python
import requests

url = "http://localhost:5000/inbox"
headers = {
    "Authorization": "Bearer your_access_token"
}

response = requests.get(url, headers=headers)
print(response.json())
```

### 3. 获取发件箱消息
**请求URL:** `/outbox`
**方法:** GET

**响应示例:**
```json
{
    "messages": [
        {
            "id": 123,
            "receiver_id": "接收者ID",
            "encrypted_content": "加密的消息内容",
            "timestamp": "2024-01-01T12:00:00"
        }
    ]
}
```

**调用示例:**

curl:
```bash
curl -X GET http://localhost:5000/outbox \
  -H "Authorization: Bearer your_access_token"
```

Python:
```python
import requests

url = "http://localhost:5000/outbox"
headers = {
    "Authorization": "Bearer your_access_token"
}

response = requests.get(url, headers=headers)
print(response.json())
```

### 4. 授予消息权限
**请求URL:** `/message/<message_id>/permission`
**方法:** POST

**请求参数:**
```json
{
    "user_id": "要授权的用户ID",
    "permission_type": "权限类型(read/write/admin)"
}
```

**响应示例:**
```json
{
    "message": "Permission granted successfully"
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/message/123/permission"
headers = {
    "Authorization": "Bearer your_access_token",
    "Content-Type": "application/json"
}
data = {
    "user_id": "user456",
    "permission_type": "read"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

### 5. 撤销消息权限
**请求URL:** `/message/<message_id>/permission`
**方法:** DELETE

**请求参数:**
```json
{
    "user_id": "要撤销权限的用户ID"
}
```

**响应示例:**
```json
{
    "message": "Permission revoked successfully"
}
```

**调用示例:**



Python:
```python
import requests

url = "http://localhost:5000/message/123/permission"
headers = {
    "Authorization": "Bearer your_access_token",
    "Content-Type": "application/json"
}
data = {
    "user_id": "user456"
}

response = requests.delete(url, headers=headers, json=data)
print(response.json())
```

## 错误处理
所有API在发生错误时会返回相应的HTTP状态码和错误信息：

- 400: 请求参数缺失或格式错误
- 403: 权限不足
- 404: 资源不存在
- 500: 服务器内部错误

