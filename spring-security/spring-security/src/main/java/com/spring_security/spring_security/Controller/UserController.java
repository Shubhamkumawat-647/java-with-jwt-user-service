package com.spring_security.spring_security.Controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import com.spring_security.spring_security.entity.AuthRequest;
import com.spring_security.spring_security.entity.UserInfo;
import com.spring_security.spring_security.responce.AuthResponse;
import com.spring_security.spring_security.service.JwtService;
import com.spring_security.spring_security.service.UserInfoService;

@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserInfoService service;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome this endpoint is not secure";
    }

    @PostMapping("/addNewUser")
    public String addNewUser(@RequestBody UserInfo userInfo) {
        return service.addUser(userInfo);
    }

    @GetMapping("/user/getAll")
//    @PreAuthorize("hasAuthority('ROLE_USER')")
    public List<UserInfo> getAllUsersWithUserRole() {
        return service.getUsersBasedOnRole();
    }
    
//method based
    @GetMapping("/admin/getAll")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String adminProfile() {
        return "Welcome to Admin Profile";
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );

            if (authentication.isAuthenticated()) {
                String token = jwtService.generateToken(authRequest.getUsername());
                UserDetails userDetails = service.loadUserByUsername(authRequest.getUsername());

                // Populate user details into a map (e.g., username and roles)
                Map<String, Object> userDetailsMap = new HashMap<>();
                userDetailsMap.put("username", userDetails.getUsername());
                userDetailsMap.put("roles", userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()));

                AuthResponse response = new AuthResponse(token, userDetailsMap);
                return ResponseEntity.ok(response);
            } else {
                throw new UsernameNotFoundException("Invalid user request!");
            }
        } catch (Exception e) {
            e.printStackTrace(); // Log for debugging
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        }
    }


}
