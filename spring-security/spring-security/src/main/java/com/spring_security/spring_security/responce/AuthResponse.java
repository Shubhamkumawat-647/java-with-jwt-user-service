package com.spring_security.spring_security.responce;

import java.util.Map;

public class AuthResponse {
    private String token;
    private Map<String, Object> userDetails;

    public AuthResponse(String token, Map<String, Object> userDetails) {
        this.token = token;
        this.userDetails = userDetails;
    }

    // Getters and setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Map<String, Object> getUserDetails() {
        return userDetails;
    }

    public void setUserDetails(Map<String, Object> userDetails) {
        this.userDetails = userDetails;
    }
}
