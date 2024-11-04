package com.spring_security.spring_security.repository;

import com.spring_security.spring_security.entity.UserInfo;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UerInfoResposetory extends JpaRepository<UserInfo, Integer> {
	@Query("SELECT u FROM UserInfo u WHERE u.email = ?1")
	List<UserInfo> findByEmail(String email);

	@Query("SELECT u FROM UserInfo u WHERE u.roles = 'ROLE_USER'")
	List<UserInfo> findByUserRole();

}
