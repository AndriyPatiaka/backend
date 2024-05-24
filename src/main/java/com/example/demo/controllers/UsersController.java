package com.example.demo.controllers;

import com.example.demo.models.User;
import com.example.demo.models.JwtUtil;
import com.example.demo.repositories.UserRepository;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
public class UsersController {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder encoder;

    public UsersController(UserRepository userRepository, JwtUtil jwtUtil, BCryptPasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.encoder = encoder;
    }


    @PostMapping("/register")
    public ResponseEntity<?> registerCandidate(@RequestBody User user) {
        User savedUser = userRepository.save(user);
        final String token = jwtUtil.generateToken(savedUser.getUsername());
        Map<String, Object> response = new HashMap<>();
        response.put("user", savedUser);
        response.put("token", token);
        return ResponseEntity.ok(response);
    }


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Login login) {
        Optional<User> candidate = userRepository.findByUsername(login.getUsername());
        if (candidate.isPresent() && encoder.matches(login.getPassword(), candidate.get().getPassword())) {
            final String token = jwtUtil.generateToken(login.getUsername());
            return ResponseEntity.ok(token);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    @GetMapping("/user")
    public ResponseEntity<?> getUser(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Authorization token is missing or invalid");
        }
        String token = authHeader.substring(7);
        try {
            String username = jwtUtil.extractUsername(token);

            Optional<User> user = userRepository.findByUsername(username);
            if (user.isPresent()) {
                return ResponseEntity.ok(user.get());
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
        }
    }
}
@Getter
@Setter
class Login{
    private String username;
    private String password;
}