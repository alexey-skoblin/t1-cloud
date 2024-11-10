package com.t1.profile.auth_service.repository;

import com.t1.profile.auth_service.model.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepo extends CrudRepository<User, Integer> {

    User findByEmail(String email);

}
