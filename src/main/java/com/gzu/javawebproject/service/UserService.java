package com.gzu.javawebproject.service;

import com.gzu.javawebproject.entity.User;
import java.util.List;

public interface UserService {
    User register(User user);
    String login(String username, String password);
    User getUserById(Long id);
    List<User> getAllUsers();
    void deleteUser(Long id);
}
