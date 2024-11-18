package com.seclib.user.mapper;

import com.seclib.user.dto.SocialLoginUserDTO;
import com.seclib.user.model.SocialLoginUser;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface SocialLoginUserMapper {
    @Mapping(target = "csrfToken", ignore = true)
    @Mapping(target = "sessionId", ignore = true)

    SocialLoginUserDTO toSocialLoginUserDTO(SocialLoginUser user);

    SocialLoginUser fromSocialLoginUserDTO(SocialLoginUserDTO dto);
}