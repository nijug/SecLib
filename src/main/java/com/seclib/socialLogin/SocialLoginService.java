package com.seclib.socialLogin;

import com.seclib.user.dto.BaseUserDTO;
import com.seclib.user.model.BaseUser;
import jakarta.servlet.http.HttpServletRequest;

public interface SocialLoginService {
    BaseUserDTO loginViaSocial(BaseUserProfile userProfile, HttpServletRequest request);
    BaseUser findByUsername(String username);
    BaseUser findById(Long id);

}
