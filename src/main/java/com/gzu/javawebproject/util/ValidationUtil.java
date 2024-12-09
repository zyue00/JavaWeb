package com.gzu.javawebproject.util;

import java.util.Arrays;
import java.util.regex.Pattern;

public class ValidationUtil {
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");
    private static final String[] VALID_ROLES = {"student", "teacher", "admin"};

    // 检查字符串是否为空
    public static boolean isNullOrEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    // 验证邮箱格式
    public static boolean isValidEmail(String email) {
        return EMAIL_PATTERN.matcher(email).matches();
    }

    // 验证角色是否有效
    public static boolean isValidRole(String role) {
        return Arrays.asList(VALID_ROLES).contains(role);
    }
}
