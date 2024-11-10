package com.t1.profile.auth_service.common.web.config;

import com.t1.profile.auth_service.model.Role;
import com.t1.profile.auth_service.model.User;
import com.t1.profile.auth_service.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        if (userRepo.findByEmail("admin@admin.admin") == null) {
            User adminUser = new User();
            adminUser.setEmail("admin@admin.admin");
            adminUser.setFirstName("Admin");
            adminUser.setLastName("User");
            adminUser.setPasswordHash(passwordEncoder.encode("123456"));

            adminUser.setRoles(Set.of(Role.ROLE_USER, Role.ROLE_ADMIN));

            userRepo.save(adminUser);
        }
    }

}
