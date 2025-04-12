
# API 接口说明

## 文件操作

### POST /upload
- **参数**: `username`, `auth`, `filename`, `encrypted_content`
- **调用**: `POST /upload` with JSON body
- **响应**: 
  - 成功: `{"status": "success", "file": "File uploaded successfully", "file_id": id}`
  - 失败: `{"status": "error", "message": "Failed to upload file"}`

### GET /download
- **参数**: `username`, `auth`, `filename`
- **调用**: `GET /download?username=x&auth=y&filename=z`
- **响应**:
  - 成功: `{"status": "success", "encrypted_content": "..."}`
  - 失败: `{"status": "error", "message": "Failed to download file"}`

### POST /ask_share
- **参数**: `username`, `auth`, `filename`, `to_user`
- **调用**: `POST /ask_share` with JSON body
- **响应**:
  - 成功: `{"status": "success", "target_public_key": "...", "encrypted_content": "..."}`
  - 失败: `{"status": "error", "message": "Failed to process share request"}`

### POST /confirm_share
- **参数**: `username`, `auth`, `filename`, `to_user`, `encrypted_content` 
- **调用**: `POST /confirm_share` with JSON body
- **响应**:
  - 成功: `{"status": "success", "file": "File shared successfully", "new_file_id": id}`
  - 失败: `{"status": "error", "message": "Failed to complete file sharing"}`

### DELETE /delete
- **参数**: `username`, `auth`, `filename`
- **调用**: `DELETE /delete?username=x&auth=y&filename=z`
- **响应**:
  - 成功: `{"status": "success", "file": "File deleted successfully"}`
  - 失败: `{"status": "error", "message": "Failed to delete file"}`

### PUT /update
- **参数**: `username`, `auth`, `filename`, `encrypted_content`
- **调用**: `PUT /update` with JSON body
- **响应**:
  - 成功: `{"status": "success", "file": "File updated successfully", "file_id": id}`
  - 失败: `{"status": "error", "message": "Failed to update file"}`

## 用户认证

### POST /register
- **参数**: `user_id`, `password_hash`, `public_key`, `email`(可选)
- **调用**: `POST /register` with JSON body
- **响应**:
  - 成功: `{"status": "success", "file": "User registered successfully", "data": {...}}`
  - 失败: `{"status": "error", "file": "错误信息"}`

### POST /login
- **参数**: `user_id`, `password_hash`, `signature`
- **调用**: `POST /login` with JSON body
- **响应**:
  - 成功: `{"status": "success", "file": "User logged in successfully"}`
  - 失败: `{"status": "error", "file": "错误信息"}`

### GET /public_key
- **参数**: `user_id`
- **调用**: `GET /public_key?user_id=x`
- **响应**:
  - 成功: `{"status": "success", "data": {"user_id": "...", "public_key": "..."}}`
  - 失败: `{"status": "error", "file": "错误信息"}`

### POST /reset
- **参数**: `user_id`, `current_password_hash`, `new_password_hash`, `signature`(可选)
- **调用**: `POST /reset` with JSON body
- **响应**:
  - 成功: `{"status": "success", "file": "Password changed successfully"}`
  - 失败: `{"status": "error", "file": "错误信息"}`

### GET /logs
- **参数**: `user_id`
- **调用**: `GET /logs?user_id=x`
- **响应**:
  - 成功: `{"status": "success", "logs": [...]}`
  - 失败: `{"status": "error", "file": "错误信息"}`

---

**说明**: 所有接口使用简化的验证机制，仅通过用户名和密码哈希进行用户识别。文件操作通过加密内容传输，保证数据安全性。接口统一返回JSON格式，成功状态码分别为200(成功操作)和201(创建成功)，失败状态码为400(请求错误)、404(资源不存在)或500(服务器错误)。
