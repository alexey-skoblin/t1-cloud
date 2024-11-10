package com.t1.profile.auth_service.security.details;

import com.t1.profile.auth_service.exception.UserNotFoundException;
import com.t1.profile.auth_service.model.User;
import com.t1.profile.auth_service.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepo.findByEmail(email);
        if (user == null) {
            throw new UserNotFoundException(email);
        }
        return new UserDetailsImpl(user);
    }

}
