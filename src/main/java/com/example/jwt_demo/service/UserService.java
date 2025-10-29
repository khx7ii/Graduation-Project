package com.example.jwt_demo.service;

import com.example.jwt_demo.model.User;
import com.example.jwt_demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // ✅ تحميل المستخدم من قاعدة البيانات لاستخدامه داخل Security
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword())
                .authorities("USER")
                .build();
    }

    // ✅ تسجيل مستخدم جديد (MongoDB)
    public boolean registerUser(String username, String email, String password) {
        if (userRepository.findByUsername(username).isPresent()) {
            return false; // Username already exists
        }

        String hashedPassword = passwordEncoder.encode(password);

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(hashedPassword);

        userRepository.save(user);
        return true;
    }

    // ✅ تسجيل الدخول
    public boolean loginUser(String username, String password) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) return false;

        User user = userOpt.get();
        return passwordEncoder.matches(password, user.getPassword());
    }

    // ✅ توليد refresh token عشوائي
    public String generateRefreshToken() {
        byte[] randomBytes = new byte[64];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    // ✅ حفظ refresh token في قاعدة البيانات
    public void storeRefreshTokenForUser(String username, String refreshToken, long validMillis) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        String hash = passwordEncoder.encode(refreshToken);
        user.setRefreshTokenHash(hash);
        user.setRefreshTokenExpiry(new Date(System.currentTimeMillis() + validMillis));
        userRepository.save(user);
    }

    // ✅ التحقق من صلاحية refresh token
    public boolean validateRefreshToken(String username, String refreshToken) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) return false;

        User user = userOpt.get();
        if (user.getRefreshTokenHash() == null) return false;
        if (user.getRefreshTokenExpiry() == null || user.getRefreshTokenExpiry().before(new Date())) return false;

        return passwordEncoder.matches(refreshToken, user.getRefreshTokenHash());
    }

    // ✅ إلغاء refresh token
    public void revokeRefreshToken(String username) {
        userRepository.findByUsername(username).ifPresent(u -> {
            u.setRefreshTokenHash(null);
            u.setRefreshTokenExpiry(null);
            userRepository.save(u);
        });
    }

    // ✅ للبحث عن المستخدم
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
