package com.gzu.javawebproject.util;

import java.util.HashMap;
import java.util.Map;

public class ResponseUtil {
    // 成功响应
    public static Map<String, Object> success(Object data) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("data", data);
        return response;
    }

    // 错误响应
    public static Map<String, Object> error(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "error");
        response.put("message", message);
        return response;
    }
}
