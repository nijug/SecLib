package com.seclib.loginAttempt.repository;

import com.seclib.loginAttempt.model.DefaultLoginAttempt;
import org.springframework.stereotype.Repository;

@Repository
public interface DefaultLoginAttemptRepository extends BaseLoginAttemptRepository<DefaultLoginAttempt, Long> {

}