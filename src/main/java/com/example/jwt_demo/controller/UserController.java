package com.example.jwt_demo.controller;

import com.example.jwt_demo.model.User;
import com.example.jwt_demo.service.UserService;
import com.example.jwt_demo.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.Optional;

@RestController
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil; // ✅ استخدمناه بدل الطرق الـ static

    // ---------------------- REGISTER ----------------------
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String email = body.get("email");
        String password = body.get("password");

        boolean ok = userService.registerUser(username, email, password);
        if (!ok) return ResponseEntity.badRequest().body(Map.of("error", "Username already exists"));

        return ResponseEntity.ok(Map.of("message", "User registered successfully"));
    }

    // ---------------------- LOGIN ----------------------
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body, HttpServletResponse response) {
        String username = body.get("username");
        String password = body.get("password");

        if (!userService.loginUser(username, password))
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));

        String accessToken = jwtUtil.generateAccessToken(username); // ✅
        String refreshToken = userService.generateRefreshToken();

        // حفظ refresh token في المستخدم
        userService.storeRefreshTokenForUser(username, refreshToken, 7L * 24 * 60 * 60 * 1000); // 7 أيام

        // إضافة refreshToken كـ Cookie آمن
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // خليه true في حالة HTTPS
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7 أيام
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of(
                "accessToken", accessToken,
                "message", "Login successful"
        ));
    }

    // ---------------------- REFRESH TOKEN ----------------------
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = null;

        // استخراج الكوكي
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("refreshToken".equals(c.getName())) {
                    refreshToken = c.getValue();
                }
            }
        }

        if (refreshToken == null)
            return ResponseEntity.status(401).body(Map.of("error", "Missing refresh token"));

        // استخراج username من الـ token نفسه
        String username;
        try {
            username = jwtUtil.extractUsername(refreshToken); // ✅
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid refresh token"));
        }

        // تحقق من صلاحية refresh token
        if (!userService.validateRefreshToken(username, refreshToken))
            return ResponseEntity.status(401).body(Map.of("error", "Invalid or expired token"));

        // توليد توكنات جديدة (token rotation)
        String newAccessToken = jwtUtil.generateAccessToken(username); // ✅
        String newRefreshToken = userService.generateRefreshToken();

        userService.storeRefreshTokenForUser(username, newRefreshToken, 7L * 24 * 60 * 60 * 1000);

        Cookie cookie = new Cookie("refreshToken", newRefreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of(
                "accessToken", newAccessToken,
                "message", "Token refreshed successfully"
        ));
    }

    // ---------------------- LOGOUT ----------------------
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        String username = null;

        // استخرجي username من الـ refresh token لو موجود
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("refreshToken".equals(c.getName())) {
                    try {
                        username = jwtUtil.extractUsername(c.getValue()); // ✅
                    } catch (Exception ignored) {}
                }
            }
        }

        if (username != null)
            userService.revokeRefreshToken(username);

        // امسحي الكوكي
        Cookie cookie = new Cookie("refreshToken", "");
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    // ---------------------- PROFILE ----------------------
    @GetMapping("/profile")
    public ResponseEntity<?> profile(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(Map.of("error", "Missing or invalid Authorization header"));
        }

        String token = authHeader.substring(7);
        String username;

        try {
            username = jwtUtil.extractUsername(token); // ✅
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
        }

        if (jwtUtil.isTokenExpired(token)) { // ✅
            return ResponseEntity.status(401).body(Map.of("error", "Token expired"));
        }

        Optional<User> userOpt = userService.findByUsername(username);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        User user = userOpt.get();
        return ResponseEntity.ok(Map.of(
                "username", user.getUsername(),
                "email", user.getEmail(),
                "message", "Welcome, " + user.getUsername()
        ));
    }
}
