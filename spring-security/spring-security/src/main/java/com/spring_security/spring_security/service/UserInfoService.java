package com.spring_security.spring_security.service;

import com.spring_security.spring_security.entity.UserInfo;
import com.spring_security.spring_security.repository.UerInfoResposetory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

import javax.persistence.NonUniqueResultException;

@Service
public class UserInfoService implements UserDetailsService {

    @Autowired
    private UerInfoResposetory repository;

    @Autowired
    private PasswordEncoder encoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<UserInfo> userDetailList = repository.findByEmail(username);

        if (userDetailList.size() > 1) {
            throw new NonUniqueResultException("Multiple users found with the same email: " + username);
        }

        return userDetailList.stream()
            .findFirst() // Return the first user found
            .map(UserInfoDetails::new)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }


    public String addUser(UserInfo userInfo) {
        // Encode password before saving the user
        userInfo.setPassword(encoder.encode(userInfo.getPassword()));
        repository.save(userInfo);
        return "User Added Successfully";
    }
    public List<UserInfo> getUsersBasedOnRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Check if the user has ROLE_ADMIN
        if (authentication.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"))) {
            // If admin, return all users
            return repository.findAll();
        } else {
            // If not admin, return only users with ROLE_USER
            return repository.findByUserRole();
        }
    }
}
