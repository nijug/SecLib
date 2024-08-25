package com.seclib.user.mapper;

import com.seclib.user.dto.DefaultUserDTO;
import com.seclib.user.model.DefaultUser;
import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface DefaultUserMapper{
    @Mapping(target = "totpSecret", source = "totpSecret")
    @Mapping(target = "csrfToken", ignore = true)
    DefaultUserDTO toDefaultUserDTO(DefaultUser user);

    @InheritInverseConfiguration
    @Mapping(target = "failedAttempts", ignore = true)
    @Mapping(target = "lockTime", ignore = true)
    DefaultUser fromDefaultUserDTO(DefaultUserDTO dto);
}