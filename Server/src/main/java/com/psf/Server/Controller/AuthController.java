package com.psf.Server.Controller;

import com.psf.Server.Utils.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtUtil jwtUtil;

    private final String ADMIN_USER = "admin";
    private final String ADMIN_PASS = "test";

    public AuthController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        System.out.println("Received username=" + username + " password=" + password);

        if (ADMIN_USER.equals(username) && ADMIN_PASS.equals(password)) {
            String token = jwtUtil.generateToken(username, "admin");
            return ResponseEntity.ok(Map.of("token", token));
        } else {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }
    }
}