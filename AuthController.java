package com.example.finance.controller;

import com.example.finance.DTO.UserDTO;
import com.example.finance.entity.User;
import com.example.finance.security.JwtUtil;
import com.example.finance.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserDTO userDTO) {
        try {
            User user = userService.registerUser(userDTO);
            return ResponseEntity.ok("User registered successfully");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody UserDTO userDTO) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userDTO.getUsername(), userDTO.getPassword())
            );
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Incorrect username or password");
        }

        final UserDetails userDetails = userService.loadUserByUsername(userDTO.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails.getUsername()); // Pass the username to generateToken

        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("token", jwt);
        return ResponseEntity.ok(tokenMap);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        // JWT is stateless, so just return a success message
        return ResponseEntity.ok("Logged out successfully");
    }
}