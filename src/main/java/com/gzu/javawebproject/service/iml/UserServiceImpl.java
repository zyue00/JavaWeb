package com.gzu.javawebproject.service.iml;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.gzu.javawebproject.entity.User;
import com.gzu.javawebproject.mapper.UserMapper;
import com.gzu.javawebproject.service.UserService;
import com.gzu.javawebproject.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserMapper userMapper;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public User register(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userMapper.insert(user);
        return user;
    }

    @Override
    public String login(String username, String password) {
        User user = userMapper.selectOne(new QueryWrapper<User>().eq("username", username));
        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            // 提取 username 和 role

            String role = user.getRole();  // 假设 User 类有 role 字段

            // 生成并返回 token
            return JwtUtil.generateToken(username, role);
        }
        throw new RuntimeException("Invalid username or password");
    }

    @Override
    public User getUserById(Long id) {
        return userMapper.selectById(id);
    }

    @Override
    public List<User> getAllUsers() {
        return userMapper.selectList(null);
    }

    @Override
    public void deleteUser(Long id) {
        userMapper.deleteById(id);
    }
}
