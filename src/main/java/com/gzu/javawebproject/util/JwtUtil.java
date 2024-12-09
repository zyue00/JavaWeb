package com.gzu.javawebproject.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

public class JwtUtil {
    private static final String SECRET_KEY = "SecretKey"; // 替换为安全的密钥
    private static final long EXPIRATION_TIME = 86400000; // 1天 (单位：毫秒)

    // 生成 Token
    public static String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }

    // 验证 Token 并解析
    public static Claims validateToken(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }

    // 从 Token 中获取用户名
    public static String getUsernameFromToken(String token) {
        return validateToken(token).getSubject();
    }

    // 从 Token 中获取角色
    public static String getRoleFromToken(String token) {
        return (String) validateToken(token).get("role");
    }
}
