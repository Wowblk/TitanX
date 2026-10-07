**关键词检索**

- 请求示例（匿名）
  ```
  GET /api/v1/search?q=java&size=20&tags=Spring,事务
  ```

- 请求示例（登录）
  ```
  GET /api/v1/search?q=java&size=20&after=MC45OTk5OTk5OTk5LDIwMjQxMjMxMjM0LDEwMCwxMDAwLDEwMDA=
  Authorization: Bearer eyJhbGciOi...<省略>...XVCJ9
  ```

- 响应示例（JSON）
  ```json
  {
    "items": [
      {
        "id": "1001",
        "title": "深入理解 Spring 事务传播行为",
        "description": "<em>Spring</em> 事务传播行为详解：REQUIRED 与 REQUIRES_NEW 的差异...",
        "coverImage": "https://cdn.example.com/posts/1001/cover.jpg",
        "tags": ["Java", "Spring"],
        "authorAvatar": "https://cdn.example.com/u/42/avatar.png",
        "authorNickname": "小明",
        "tagJson": "[\"后端\",\"校友\"]",
        "likeCount": 128,
        "favoriteCount": 56,
        "liked": true,
        "faved": false,
        "isTop": false
      },
      {
        "id": "1000",
        "title": "Spring 事务失效的常见原因",
        "description": "常见事务失效场景：自调用、非 public 方法、final 方法等",
        "coverImage": null,
        "tags": ["Java", "Spring"],
        "authorAvatar": "https://cdn.example.com/u/7/avatar.png",
        "authorNickname": "后端同学",
        "tagJson": "[\"技术\",\"Java\"]",
        "likeCount": 342,
        "favoriteCount": 201,
        "liked": false,
        "faved": true,
        "isTop": false
      }
    ],
    "nextAfter": "MC45OTk5OTk5OTk5LDIwMjQxMjMxMjM0LDM0MiwzMjE0LDEwMDA=",
    "hasMore": true
  }
  ```

**联想建议**

- 请求示例
  ```
  GET /api/v1/search/suggest?prefix=jav&size=5
  ```

- 响应示例（JSON）
  ```json
  {
    "items": [
      "Java 并发编程",
      "Java 虚拟机调优",
      "Java 内存模型",
      "Java 泛型最佳实践",
      "Java Stream API"
    ]
  }
  ```