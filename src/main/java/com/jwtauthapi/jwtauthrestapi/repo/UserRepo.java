package com.jwtauthapi.jwtauthrestapi.repo;

import com.jwtauthapi.jwtauthrestapi.model.AppUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);
    Page<AppUser> findAllByUsername(String username, Pageable pageable);
}
