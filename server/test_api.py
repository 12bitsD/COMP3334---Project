import requests
import json
import time
import traceback
import sys

BASE_URL = "http://localhost:5000"

def test_api(endpoint, method="GET", data=None, params=None, debug=False):
    url = f"{BASE_URL}{endpoint}"
    
    print(f"\n{method} {url}")
    if data:
        print(f"请求数据: {json.dumps(data, indent=2, ensure_ascii=False)}")
    if params:
        print(f"查询参数: {json.dumps(params, indent=2, ensure_ascii=False)}")
    
    try:
        if method == "GET":
            response = requests.get(url, params=params, timeout=10)
        elif method == "POST":
            response = requests.post(url, json=data, timeout=10)
        elif method == "PUT":
            response = requests.put(url, json=data, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, json=data, timeout=10)
        else:
            raise ValueError(f"不支持的HTTP方法: {method}")
        
        print(f"状态码: {response.status_code}")
        
        try:
            json_resp = response.json()
            print(f"响应: {json.dumps(json_resp, indent=2, ensure_ascii=False)}")
            return response.status_code, json_resp
        except json.JSONDecodeError:
            print(f"响应不是有效的JSON: {response.text[:500]}")
            return response.status_code, response.text
            
    except requests.exceptions.RequestException as e:
        print(f"错误: {e}")
        if debug:
            print("详细错误信息:")
            traceback.print_exc()
        return None, None

def main():
    print("等待服务器启动...")
    time.sleep(2)
    
    # 测试认证相关API
    print("\n========== 测试认证相关API ==========")
    
    # 注册带邮箱的用户
    print("\n1. 注册带邮箱的用户")
    register_data = {
        "user_id": "testuser4",  # 使用一个新的用户名来避免冲突
        "password_hash": "testhash",
        "public_key": "testkey",
        "email": "test@example.com"  # 添加邮箱
    }
    test_api("/auth/register", "POST", register_data)
    
    # 登录
    print("\n2. 用户登录")
    login_data = {
        "user_id": "testuser4",  # 使用相同的新用户名
        "password_hash": "testhash",
        "signature": "testsignature"
    }
    test_api("/auth/login", "POST", login_data)
    
    # 获取公钥
    print("\n3. 获取公钥")
    test_api("/auth/public_key", "GET", params={"user_id": "testuser4"})  # 使用相同的新用户名
    
    # 重置密码 - 修复参数
    print("\n4. 重置密码")
    reset_data = {
        "user_id": "testuser4",  # 使用相同的新用户名
        "current_password_hash": "testhash",
        "password_hash": "newhash",
        "signature": "testsignature"
    }
    test_api("/auth/reset", "POST", reset_data, debug=True)
    
    # 获取用户日志
    print("\n5. 获取用户日志")
    logs_data = {
        "user_id": "testuser4",  # 使用相同的新用户名
        "signature": "testsignature"
    }
    test_api("/auth/logs", "GET", params=logs_data)
    
    # 请求OTP (带邮箱的用户)
    print("\n6. 请求OTP")
    otp_data = {
        "user_id": "testuser4",  # 使用相同的新用户名
        "signature": "testsignature"
    }
    test_api("/auth/otp/request", "POST", otp_data, debug=True)
    
    # 测试文件相关API
    print("\n========== 测试文件相关API ==========")
    
    # 上传文件
    print("\n7. 上传文件")
    upload_data = {
        "username": "testuser4",  # 使用相同的新用户名
        "auth": "newhash",       # 使用更新后的密码
        "filename": "testfile.txt",
        "encrypted_content": "encryptedcontent",
        "hmac": "testsignature"
    }
    upload_status, upload_response = test_api("/files/upload", "POST", upload_data, debug=True)
    
    # 获取文件ID
    file_id = None
    if upload_status == 201 and upload_response and isinstance(upload_response, dict) and "file_id" in upload_response:
        file_id = upload_response["file_id"]
        print(f"\n成功获取文件ID: {file_id}")
    else:
        print("\n上传失败或响应格式错误，使用默认文件ID：1")
        file_id = "1"
    
    # 下载文件
    print("\n8. 下载文件")
    download_params = {
        "username": "testuser4",  # 使用相同的新用户名
        "auth": "newhash",       # 使用更新后的密码
        "filename": "testfile.txt",
        "hmac": "testsignature"
    }
    test_api("/files/download", "GET", params=download_params, debug=True)
    
    # 创建另一个用户用于共享
    print("\n创建另一个用户用于共享")
    share_user_data = {
        "user_id": "testuser5",
        "password_hash": "testhash",
        "public_key": "testkey2",
        "email": "test2@example.com"
    }
    test_api("/auth/register", "POST", share_user_data)
    
    # 请求共享 - 先尝试获取另一个用户ID
    print("\n9. 请求共享文件")
    share_data = {
        "action": "ask_share",
        "username": "testuser4",  # 使用相同的新用户名
        "auth": "newhash",       # 使用更新后的密码
        "filename": "testfile.txt",
        "to_user": "testuser5",  # 使用新创建的用户
        "hmac": "testsignature"
    }
    test_api("/files/ask_share", "POST", share_data, debug=True)
    
    # 确认共享
    print("\n10. 确认共享")
    confirm_data = {
        "action": "confirm_share",
        "username": "testuser4",  # 使用相同的新用户名
        "auth": "newhash",       # 使用更新后的密码
        "filename": "testfile.txt",
        "to_user": "testuser5",  # 使用新创建的用户
        "encrypted_content": "encryptedcontentforsharing",
        "hmac": "testsignature"
    }
    test_api("/files/confirm_share", "POST", confirm_data, debug=True)
    
    # 查询待处理共享
    print("\n11. 查询待处理共享")
    pending_params = {
        "username": "testuser4",  # 使用相同的新用户名
        "auth": "newhash",       # 使用更新后的密码
        "hmac": "testsignature"
    }
    test_api("/files/pending_shares", "GET", params=pending_params, debug=True)
    
    # 更新文件
    print("\n12. 更新文件")
    update_data = {
        "username": "testuser4",  # 使用相同的新用户名
        "auth": "newhash",       # 使用更新后的密码
        "filename": "testfile.txt",
        "encrypted_content": "updatedcontent",
        "hmac": "testsignature"
    }
    test_api("/files/update", "PUT", update_data, debug=True)
    
    # 删除文件
    print("\n13. 删除文件")
    delete_data = {
        "username": "testuser4",  # 使用相同的新用户名
        "auth": "newhash",       # 使用更新后的密码
        "filename": "testfile.txt",
        "hmac": "testsignature"
    }
    test_api("/files/delete", "DELETE", delete_data, debug=True)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"测试执行过程中发生错误: {e}")
        traceback.print_exc() 