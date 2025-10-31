package com.example.jwt_demo.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@Document(collection = "users")
public class User {
    @Id
    private String id;

    private String username; // ✅ مجرد display name

    @Indexed(unique = true) // ✅ يجعل الإيميل فريد في الـ collection
    private String email;

    private String password;

    private String refreshTokenHash;
    private Date refreshTokenExpiry;

    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }
}
