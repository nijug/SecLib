package com.seclib.user.repository;
import com.seclib.user.model.DefaultUser;
import org.springframework.stereotype.Repository;

@Repository
public interface DefaultUserRepository extends BaseUserRepository<DefaultUser, Long> {
}