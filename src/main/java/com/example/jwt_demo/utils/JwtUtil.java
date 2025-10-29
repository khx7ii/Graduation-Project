package com.example.jwt_demo.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    private static final String SECRET_KEY = "my_super_secret_key_12345678901234567890"; // خليها طويلة وقوية
    private static final long EXPIRATION_TIME = 1000 * 60 * 60; // ساعة واحدة

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    // ✅ إنشاء Access Token جديد
    public String generateAccessToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ✅ استخراج اسم المستخدم من التوكن
    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    // ✅ فحص انتهاء صلاحية التوكن
    public boolean isTokenExpired(String token) {
        return parseClaims(token).getExpiration().before(new Date());
    }

    // ✅ التحقق من صحة التوكن
    public boolean validateToken(String token, String username) {
        return username.equals(extractUsername(token)) && !isTokenExpired(token);
    }

    // ✅ دالة مساعدة لاستخراج الـ Claims (المعلومات بداخل التوكن)
    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
