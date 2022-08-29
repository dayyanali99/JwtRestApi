package com.jwtauthapi.jwtauthrestapi.service;

import com.jwtauthapi.jwtauthrestapi.model.AppUser;
import com.jwtauthapi.jwtauthrestapi.model.Role;
import com.jwtauthapi.jwtauthrestapi.repo.RoleRepo;
import com.jwtauthapi.jwtauthrestapi.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetailsImpl userDetails = userRepo.findByUsername(username)
                .stream().findFirst().map(UserDetailsImpl::new).orElseThrow(() -> {
                    log.error("User not found in the database");
                    throw new UsernameNotFoundException(username + " NOT FOUND!");
                });
        log.info("User found in the database");
        return userDetails;
    }

    @Override
    public AppUser saveUser(AppUser user) {
        log.info("Saving new user {} to the database", user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role {} to the database", role.getName());
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", roleName, username);

        AppUser user = userRepo.findByUsername(username)
                .stream().findFirst().orElseThrow();

        Role role = roleRepo.findByName(roleName)
                .stream().findFirst().orElseThrow(() -> new EntityNotFoundException(roleName + " not found!"));

        user.getRoles().add(role);
    }

    @Override
    public AppUser getUser(String username) {
        log.info("Fetching user {}", username);
        return userRepo.findByUsername(username)
                .stream().findFirst().orElseThrow(() -> new UsernameNotFoundException(username + " not found!"));
    }

    @Override
    public List<AppUser> getUsers() {
        log.info("Fetching all users");
        return userRepo.findAll();
    }

}
