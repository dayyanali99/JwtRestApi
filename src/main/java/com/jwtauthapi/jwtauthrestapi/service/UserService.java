package com.jwtauthapi.jwtauthrestapi.service;

import com.jwtauthapi.jwtauthrestapi.model.AppUser;
import com.jwtauthapi.jwtauthrestapi.model.Role;

import java.util.List;

public interface UserService {
    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUsers();
}
