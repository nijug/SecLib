package com.seclib.socialLogin;

import com.seclib.user.dto.SocialLoginUserDTO;
import com.seclib.user.mapper.SocialLoginUserMapper;
import com.seclib.user.model.SocialLoginUser;
import com.seclib.user.repository.SocialLoginUserRepository;
import com.seclib.csrf.CsrfService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class DefaultSocialLoginService implements SocialLoginService {

    private final SocialLoginUserRepository userRepository;
    private final CsrfService csrfService;
    private final SocialLoginUserMapper userMapper;

    @Autowired
    public DefaultSocialLoginService(SocialLoginUserRepository userRepository, CsrfService csrfService, SocialLoginUserMapper userMapper) {
        this.userRepository = userRepository;
        this.csrfService = csrfService;
        this.userMapper = userMapper;
    }

    @Override
    public SocialLoginUserDTO loginViaSocial(BaseUserProfile userProfile, HttpServletRequest request) {
        SocialLoginUser user = userRepository.findByProviderAndProviderId(userProfile.getProvider(), userProfile.getProviderId()).orElse(null);
        if (user == null) {
            user = new SocialLoginUser(userProfile.getUsername(), userProfile.getProvider(), userProfile.getProviderId(), userProfile.getEmail());
            userRepository.save(user);
        }
        HttpSession newSession = createNewSessionWithAttributes(request, user);
        return createUserDTOWithCsrfToken(user, newSession);
    }

    public SocialLoginUserDTO loginViaSocial(BaseUserProfile userProfile, Optional<String> role, HttpServletRequest request) {
        SocialLoginUser user = userRepository.findByProviderAndProviderId(userProfile.getProvider(), userProfile.getProviderId()).orElse(null);
        if (user == null) {
            user = new SocialLoginUser(userProfile.getUsername(), userProfile.getProvider(), userProfile.getProviderId(), userProfile.getEmail());
            user.setRole(role.get());
            userRepository.save(user);
        }
        HttpSession newSession = createNewSessionWithAttributes(request, user);
        return createUserDTOWithCsrfToken(user, newSession);
    }


    private HttpSession createNewSessionWithAttributes(HttpServletRequest request, SocialLoginUser user) {
        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            oldSession.invalidate();
        }
        HttpSession newSession = request.getSession(true);
        newSession.setAttribute("userId", user.getId());
        return newSession;
    }

    private SocialLoginUserDTO createUserDTOWithCsrfToken(SocialLoginUser user, HttpSession session) {
        SocialLoginUserDTO userDTO = userMapper.toSocialLoginUserDTO(user);
        if (csrfService != null) {
            String csrfToken = csrfService.generateToken();
            csrfService.storeToken(session, csrfToken);
            userDTO.setCsrfToken(csrfToken);
        }
        userDTO.setSessionId(session.getId());
        return userDTO;
    }

    @Override
    public SocialLoginUserDTO findByUsername(String username) {
        return userMapper.toSocialLoginUserDTO(userRepository.findByUsername(username).orElse(null));
    }

    @Override
    public SocialLoginUser findById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

}