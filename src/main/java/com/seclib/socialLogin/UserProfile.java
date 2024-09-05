package com.seclib.socialLogin;

import lombok.Data;

@Data
public class UserProfile {
    private String id;
    private String email;
    private String name;
    private String pictureUrl;
}