### 资料模块

- 路径：`PATCH /api/v1/profile`
  - 鉴权：需要携带 `Authorization: Bearer <access_token>`
  - 内容类型：`application/json`
  - 请求体（可选字段，未提交的字段保持不变）：
    ```json
    {
      "nickname": "新的昵称",
      "bio": "个人描述",
      "gender": "MALE|FEMALE|OTHER|UNKNOWN",
      "birthday": "2000-01-01",
      "zgId": "knowflow_1234",
      "school": "同济大学"
    }
    ```
  - 成功响应（`ProfileResponse`）：
    ```json
    {
      "id": 1001,
      "nickname": "新的昵称",
      "avatar": "https://cdn.example.com/avatars/1001-1710000000000.png",
      "bio": "个人描述",
      "zgId": "knowflow_1234",
      "gender": "MALE",
      "birthday": "2000-01-01",
      "school": "同济大学",
      "phone": "13800138000",
      "email": "user@example.com"
    }
    ```
  - 可能错误：
    - `ZGID_EXISTS`：KnowFlow号已存在
    - `BAD_REQUEST`：请求不合法（未提交任何更新字段等）

- 路径：`POST /api/v1/profile/avatar`
  - 鉴权：需要携带 `Authorization: Bearer <access_token>`
  - 内容类型：`multipart/form-data`
  - 请求体：`file`（字段名）上传头像文件
  - 成功响应：同 `ProfileResponse`
  - 可能错误：
    - `BAD_REQUEST`：对象存储未配置或文件读取失败