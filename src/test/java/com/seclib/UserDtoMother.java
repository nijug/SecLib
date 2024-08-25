package com.seclib;

import com.seclib.user.dto.DefaultUserDTO;

public class UserDtoMother {

    public static DefaultUserDTO createValidDTO() {
        DefaultUserDTO userDTO = new DefaultUserDTO();
        userDTO.setUsername("testUser");
        userDTO.setPassword("Password123!");
        userDTO.setTotpSecret("12345");
        return userDTO;
    }

    public static DefaultUserDTO createNonExistentDTO() {
        DefaultUserDTO userDTO = new DefaultUserDTO();
        userDTO.setUsername("testUser2");
        userDTO.setPassword("Password123!");
        userDTO.setTotpSecret("12345");
        return userDTO;
    }

    public static DefaultUserDTO createWrongPasswordDTO() {
        DefaultUserDTO userDTO = new DefaultUserDTO();
        userDTO.setUsername("testUser");
        userDTO.setPassword("Wrong");
        userDTO.setTotpSecret("12345");
        return userDTO;
    }


}
