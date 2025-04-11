# 消息系统API文档


## API接口

### 1. 用户注册
**请求URL:** `/auth/register`
**方法:** POST

**请求参数:**
```json
{
    "user_id": "用户ID",
    "password_hash": "密码哈希值",
    "public_key": "用户公钥"
}
```

**响应示例:**
```json
{
    "status": "success",
    "message": "Registration successful",
    "data": {
        "user_id": "user123"
    }
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/auth/register"
headers = {
    "Content-Type": "application/json"
}
data = {
    "user_id": "user123",
    "password_hash": "hashed_password",
    "public_key": "your_public_key"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

### 2. 用户登录
**请求URL:** `/auth/login`
**方法:** POST

**请求参数:**
```json
{
    "user_id": "用户ID",
    "password_hash": "密码哈希值"
}
```

**说明:** 只验证用户ID和密码哈希是否在数据库中匹配，匹配则登录成功，不匹配则返回错误。

**响应示例:**
```json
{
    "status": "success",
    "message": "Login successful",
    "data": {
        "user_id": "user123"
    }
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/auth/login"
headers = {
    "Content-Type": "application/json"
}
data = {
    "user_id": "user123",
    "password_hash": "hashed_password"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

### 3. 获取用户公钥
**请求URL:** `/auth/public_key`
**方法:** GET

**请求参数:**
通过URL查询参数传递:
`/auth/public_key?user_id=user123`

**响应示例:**
```json
{
    "status": "success",
    "message": "Public key retrieved successfully",
    "data": {
        "user_id": "user123",
        "public_key": "user_public_key"
    }
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/auth/public_key?user_id=user123"
headers = {
    "Content-Type": "application/json"
}

response = requests.get(url, headers=headers)
print(response.json())
```

### 4. 修改用户密码
**请求URL:** `/auth/change_password`
**方法:** POST

**请求参数:**
```json
{
    "user_id": "用户ID",
    "current_password_hash": "当前密码哈希值",
    "new_password_hash": "新密码哈希值"
}
```

**说明:** 修改用户密码需要提供当前密码哈希和新密码哈希。系统会先验证当前密码是否正确，如果正确则更新为新密码。

**响应示例:**
```json
{
    "status": "success",
    "message": "Password changed successfully"
}
```

**错误响应示例:**
```json
{
    "status": "error",
    "message": "Invalid password"
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/auth/change_password"
headers = {
    "Content-Type": "application/json"
}
data = {
    "user_id": "user123",
    "current_password_hash": "current_hashed_password",
    "new_password_hash": "new_hashed_password"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

### 5. 发送消息
**请求URL:** `/messages/send`
**方法:** POST

**请求参数:**
```json
{
    "user_id": "发送者的用户ID",
    "receiver_id": "接收者的用户ID",
    "encrypted_content": "加密后的消息内容"
}
```

**响应示例:**
```json
{
    "message": "Message sent successfully",
    "message_id": 123,
    "timestamp": "2024-01-01T12:00:00",
    "status": "success"
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/messages/send"
headers = {
    "Content-Type": "application/json"
}
data = {
    "user_id": "sender123",
    "receiver_id": "receiver456",
    "encrypted_content": "encrypted_message_content"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

### 6. 获取收件箱消息
**请求URL:** `/messages/inbox`
**方法:** GET

**请求参数:**
通过URL查询参数传递:
`/messages/inbox?user_id=user123`

**说明:** 
当用户调用此API时，服务器会执行以下操作：
1. 查询该用户作为接收者的所有消息
2. 查询通过权限系统获得访问权限的其他用户的消息
3. 将所有消息按时间戳降序排序（最新的消息排在前面）
4. 返回包含消息列表的JSON响应

每条消息包含以下字段：
- `id`: 消息的唯一标识符
- `sender_id`: 发送者的用户ID
- `encrypted_content`: 使用接收者公钥加密的消息内容
- `timestamp`: 消息发送的时间戳（ISO 8601格式）

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
    ],
    "status": "success"
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/messages/inbox?user_id=user123"
headers = {
    "Content-Type": "application/json"
}

response = requests.get(url, headers=headers)
print(response.json())
```

### 7. 获取发件箱消息
**请求URL:** `/messages/outbox`
**方法:** GET

**请求参数:**
通过URL查询参数传递:
`/messages/outbox?user_id=user123`

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
    ],
    "status": "success"
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/messages/outbox?user_id=user123"
headers = {
    "Content-Type": "application/json"
}

response = requests.get(url, headers=headers)
print(response.json())
```

### 8. 授予消息权限
**请求URL:** `/messages/message/<message_id>/permission`
**方法:** POST

**请求参数:**
```json
{
    "user_id": "授权者的用户ID",
    "target_user_id": "被授权的用户ID",
    "permission_type": "权限类型(read/write/admin)"
}
```

**响应示例:**
```json
{
    "message": "Permission granted successfully",
    "status": "success"
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/messages/message/123/permission"
headers = {
    "Content-Type": "application/json"
}
data = {
    "user_id": "owner123",
    "target_user_id": "user456",
    "permission_type": "read"
}

response = requests.post(url, headers=headers, json=data)
print(response.json())
```

### 9. 撤销消息权限
**请求URL:** `/messages/message/<message_id>/permission`
**方法:** DELETE

**请求参数:**
```json
{
    "user_id": "撤销权限的用户ID",
    "target_user_id": "被撤销权限的用户ID"
}
```

**响应示例:**
```json
{
    "message": "Permission revoked successfully",
    "status": "success"
}
```

**调用示例:**

Python:
```python
import requests

url = "http://localhost:5000/messages/message/123/permission"
headers = {
    "Content-Type": "application/json"
}
data = {
    "user_id": "owner123",
    "target_user_id": "user456"
}

response = requests.delete(url, headers=headers, json=data)
print(response.json())
```

## 错误处理
所有API在发生错误时会返回相应的HTTP状态码和错误信息：

- 400: 请求参数缺失或格式错误
- 401: 用户验证失败
- 403: 权限不足
- 404: 资源不存在(如用户、消息等)
- 500: 服务器内部错误

**错误响应示例:**
```json
{
    "message": "错误信息",
    "status": "error"
}
```

