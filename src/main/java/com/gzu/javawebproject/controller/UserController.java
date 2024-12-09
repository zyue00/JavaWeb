package com.gzu.javawebproject.controller;

import com.gzu.javawebproject.dto.LoginRequest;
import com.gzu.javawebproject.dto.UserRegisterRequest;
import com.gzu.javawebproject.dto.UserResponse;
import com.gzu.javawebproject.entity.User;
import com.gzu.javawebproject.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    // 用户注册
    @PostMapping("/register")
    public String register(@RequestBody UserRegisterRequest request) {
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(request.getPassword());
        user.setRole(request.getRole());
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        userService.register(user);
        return "User registered successfully!";
    }

    // 用户登录
    @PostMapping("/login")
    public String login(@RequestBody LoginRequest request) {
        return userService.login(request.getUsername(), request.getPassword());
    }

    // 获取所有用户
    @GetMapping
    public List<UserResponse> getAllUsers() {
        return userService.getAllUsers().stream().map(user -> {
            UserResponse response = new UserResponse();
            response.setId(user.getId());
            response.setUsername(user.getUsername());
            response.setRole(user.getRole());
            response.setEmail(user.getEmail());
            response.setPhone(user.getPhone());
            return response;
        }).collect(Collectors.toList());
    }
}
