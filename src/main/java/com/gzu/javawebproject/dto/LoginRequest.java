package com.gzu.javawebproject.dto;

public class LoginRequest {
    private String username;
    private String password;

    // 手动创建 getter 和 setter 方法

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
