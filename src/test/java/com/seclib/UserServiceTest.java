package com.seclib;

import com.seclib.config.UserProperties;
import com.seclib.exception.LoginAttemptException;
import com.seclib.exception.UserException;
import com.seclib.loginAttempt.model.DefaultLoginAttempt;
import com.seclib.loginAttempt.service.DefaultLoginAttemptService;
import com.seclib.passwordResetToken.model.DefaultPasswordResetToken;
import com.seclib.passwordResetToken.service.DefaultPasswordResetTokenService;
import com.seclib.user.dto.DefaultUserDTO;
import com.seclib.user.mapper.DefaultUserMapper;
import com.seclib.user.model.DefaultUser;
import com.seclib.user.repository.DefaultUserRepository;
import com.seclib.user.service.DefaultUserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class UserServiceTest {

    @Mock
    private UserProperties userProperties;

    @Mock
    private DefaultUserRepository defaultUserRepository;

    @Mock
    private Argon2PasswordEncoder passwordEncoder;

    @InjectMocks
    private DefaultUserService userService;

    private DefaultUser testUser;

    @Mock
    private UserProperties.PasswordPolicy passwordPolicy;

    @Mock
    private DefaultPasswordResetTokenService passwordResetTokenService;

    @Mock
    private DefaultLoginAttemptService loginAttemptService;

    private MockHttpServletRequest request;


    private final DefaultUserMapper defaultUserMapper = Mappers.getMapper(DefaultUserMapper.class);

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        userService.setUserMapper(defaultUserMapper);

        when(userProperties.getPasswordPolicy()).thenReturn(passwordPolicy);


        Argon2PasswordEncoder realEncoder = new Argon2PasswordEncoder(16, 32, 1, 7168, 5);
        when(passwordEncoder.encode(anyString())).thenAnswer(invocation -> {
            String password = invocation.getArgument(0);
            return realEncoder.encode(password);
        });

        when(passwordPolicy.getPattern()).thenReturn(".*[A-Z].*");
        when(loginAttemptService.getLoginAttempt(anyString())).thenReturn(null);
        when(loginAttemptService.createInstance(anyString())).thenReturn(new DefaultLoginAttempt("127.0.0.1"));
        when(userProperties.getIpMaxAttempts()).thenReturn(3);
        when(userProperties.getIpLockTime()).thenReturn(1 * 60 * 1000L);
        when(userProperties.getUserMaxAttempts()).thenReturn(3);
        when(userProperties.getUserLockTime()).thenReturn(1 * 60 * 1000L);
        when(passwordEncoder.matches(anyString(), anyString())).thenAnswer(invocation -> {
            String rawPassword = invocation.getArgument(0);
            String encodedPassword = invocation.getArgument(1);
            return realEncoder.matches(rawPassword, encodedPassword);
        });
        request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");

        try {
            DefaultUserDTO testUserDTO = userService.register(UserDtoMother.createValidDTO(), Optional.empty());
            testUser = defaultUserMapper.fromDefaultUserDTO(testUserDTO);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testLoginWithAccountLockingDisabledAndExistingUser() {
        when(userProperties.isIpLockingEnabled()).thenReturn(false);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        DefaultUserDTO loggedInUser = userService.login(UserDtoMother.createValidDTO(), request);
        assertEquals(testUser.getId(), loggedInUser.getId());
    }

    @Test
    public void testLoginWithAccountLockingDisabledAndNonExistingUser() {
        when(userProperties.isIpLockingEnabled()).thenReturn(false);
        when(defaultUserRepository.findByUsername("testUser2")).thenReturn(Optional.empty());
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createNonExistentDTO(), request));
    }

    @Test
    public void testLoginWithAccountLockingDisabledAndExistingUserWithWrongPassword() {
        when(userProperties.isIpLockingEnabled()).thenReturn(false);
        when(defaultUserRepository.findById(anyLong())).thenReturn(Optional.of(testUser));
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledAndCorrectPassword() {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(loginAttemptService.getLoginAttempt("127.0.0.1"))
                .thenReturn(Optional.of(new DefaultLoginAttempt("127.0.0.1", 0, System.currentTimeMillis())));
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        DefaultUserDTO loggedInUser = userService.login(UserDtoMother.createValidDTO(), request);
        assertEquals(testUser.getId(), loggedInUser.getId());
    }

    @Test
    public void testLoginWithIpLockingEnabledAndIncorrectPassword() {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(loginAttemptService.getLoginAttempt("127.0.0.1"))
                .thenReturn(Optional.of(new DefaultLoginAttempt("127.0.0.1", 0, System.currentTimeMillis())));
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledAndCorrectPasswordButBlockedIp() {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(userProperties.getIpLockTime()).thenReturn(6000L);
        when(userProperties.getIpMaxAttempts()).thenReturn(3);
        when(loginAttemptService.getLoginAttempt("127.0.0.1"))
                .thenReturn(Optional.of(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis() - 3000)));
        assertThrows(LoginAttemptException.class, () -> userService.login(UserDtoMother.createValidDTO(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledAndIncorrectPasswordAndBlockedIp() {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);

        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(loginAttemptService.getLoginAttempt("127.0.0.1"))
                .thenReturn(Optional.of(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis() - 3000)));
        assertThrows(LoginAttemptException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledAndExceedingMaxAttempts() {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));

        Optional<DefaultLoginAttempt> firstAttempt = Optional.of(new DefaultLoginAttempt("127.0.0.1", 1, System.currentTimeMillis()));
        Optional<DefaultLoginAttempt> secondAttempt = Optional.of(new DefaultLoginAttempt("127.0.0.1", 2, System.currentTimeMillis()));
        Optional<DefaultLoginAttempt> thirdAttempt = Optional.of(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis()));

        when(loginAttemptService.getLoginAttempt("127.0.0.1")).thenReturn(firstAttempt, secondAttempt, thirdAttempt);

        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
        assertThrows(LoginAttemptException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledAndNonExistingUser() {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser2")).thenReturn(Optional.empty());
        when(loginAttemptService.getLoginAttempt("127.0.0.1"))
                .thenReturn(Optional.of(new DefaultLoginAttempt("127.0.0.1", 0, System.currentTimeMillis() - 3000)));

        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createNonExistentDTO(), request));
    }

    @Test
    public void testLoginWithIpLockingDisabledAndBlockedIp() {
        when(userProperties.isIpLockingEnabled()).thenReturn(false);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(loginAttemptService.getLoginAttempt("127.0.0.1"))
                .thenReturn(Optional.of(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis() - 3000)));
        DefaultUserDTO loggedInUser = userService.login(UserDtoMother.createValidDTO(), request);
        assertEquals(testUser.getId(), loggedInUser.getId());
    }

    @Test
    public void testLoginWithIpLockingEnabledCorrectPasswordExceedingMaxAttempts() {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(userProperties.getIpLockTime()).thenReturn(5000L);
        when(userProperties.getIpMaxAttempts()).thenReturn(3);
        when(loginAttemptService.getLoginAttempt("127.0.0.1"))
                .thenReturn(Optional.of(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis() - 3000)));
        assertThrows(LoginAttemptException.class, () -> userService.login(UserDtoMother.createValidDTO(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledIncorrectPasswordExceedingMaxAttempts() {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(userProperties.getIpMaxAttempts()).thenReturn(3);
        when(loginAttemptService.getLoginAttempt("127.0.0.1"))
                .thenReturn(Optional.of(new DefaultLoginAttempt("127.0.0.1", 5, System.currentTimeMillis() - 3000)));
        assertThrows(LoginAttemptException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledCorrectPasswordJustBlocked() {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(userProperties.getIpLockTime()).thenReturn(5000L);
        when(userProperties.getIpMaxAttempts()).thenReturn(3);
        when(loginAttemptService.getLoginAttempt("127.0.0.1"))
                .thenReturn(Optional.of(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis())));
        assertThrows(LoginAttemptException.class, () -> userService.login(UserDtoMother.createValidDTO(), request));
    }

    @Test
    public void testLoginWithIpLockingEnabledIncorrectPasswordJustBlocked() {
        when(userProperties.isIpLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(userProperties.getIpMaxAttempts()).thenReturn(3);
        when(loginAttemptService.getLoginAttempt("127.0.0.1"))
                .thenReturn(Optional.of(new DefaultLoginAttempt("127.0.0.1", 3, System.currentTimeMillis())));
        assertThrows(LoginAttemptException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testLoginWithUserLockingEnabledAndCorrectPassword() {
        when(userProperties.isUserLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        DefaultUserDTO loggedInUser = userService.login(UserDtoMother.createValidDTO(), request);
        assertEquals(testUser.getId(), loggedInUser.getId());
    }

    @Test
    public void testLoginWithUserLockingEnabledAndIncorrectPassword() {
        when(userProperties.isUserLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testLoginWithUserLockingEnabledAndCorrectPasswordButBlockedUser() {
        when(userProperties.isUserLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(userProperties.getUserLockTime()).thenReturn(6000L); // Set lockTime to 5 seconds
        when(userProperties.getUserMaxAttempts()).thenReturn(3);
        testUser.setFailedAttempts(3);
        testUser.setLockTime(System.currentTimeMillis() - 3000);
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createValidDTO(), request));
    }

    @Test
    public void testLoginWithUserLockingEnabledAndIncorrectPasswordAndBlockedUser() {
        when(userProperties.isUserLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        testUser.setFailedAttempts(3);
        testUser.setLockTime(System.currentTimeMillis() - 3000);
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testLoginWithUserLockingEnabledAndExceedingMaxAttempts() {
        when(userProperties.isUserLockingEnabled()).thenReturn(true);
        when(userProperties.getUserMaxAttempts()).thenReturn(2);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));

        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));

        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));

        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testLoginWithUserLockingEnabledCorrectPasswordExceedingMaxAttempts() {
        when(userProperties.isUserLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(userProperties.getUserLockTime()).thenReturn(5000L);
        when(userProperties.getUserMaxAttempts()).thenReturn(3);
        testUser.setFailedAttempts(5);
        testUser.setLockTime(System.currentTimeMillis() - 3000);
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createValidDTO(), request));
    }

    @Test
    public void testLoginWithUserLockingEnabledIncorrectPasswordExceedingMaxAttempts() {
        when(userProperties.isUserLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(userProperties.getUserMaxAttempts()).thenReturn(3);
        testUser.setFailedAttempts(5);
        testUser.setLockTime(System.currentTimeMillis() - 3000);
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testLoginWithUserLockingEnabledCorrectPasswordJustBlocked() {
        when(userProperties.isUserLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(userProperties.getUserLockTime()).thenReturn(5000L);
        when(userProperties.getUserMaxAttempts()).thenReturn(3);
        testUser.setFailedAttempts(3);
        testUser.setLockTime(System.currentTimeMillis());
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createValidDTO(), request));
    }

    @Test
    public void testLoginWithUserLockingEnabledIncorrectPasswordJustBlocked() {
        when(userProperties.isUserLockingEnabled()).thenReturn(true);
        when(defaultUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testUser));
        when(userProperties.getUserMaxAttempts()).thenReturn(3);
        testUser.setFailedAttempts(3);
        testUser.setLockTime(System.currentTimeMillis());
        assertThrows(UserException.class, () -> userService.login(UserDtoMother.createWrongPasswordDTO(), request));
    }

    @Test
    public void testResetPassword() throws InterruptedException {
        when(userProperties.isPasswordResetEnabled()).thenReturn(true);
        String newPassword = "newPassword123!";
        DefaultPasswordResetToken resetToken = new DefaultPasswordResetToken();
        resetToken.setUser(testUser);

        when(defaultUserRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.of(testUser));
        when(passwordResetTokenService.createPasswordResetToken(testUser)).thenReturn(resetToken);
        when(passwordResetTokenService.getPasswordResetToken(resetToken.getToken())).thenReturn(Optional.of(resetToken));

        String token = userService.forgotPassword(testUser.getUsername());
        userService.resetPassword(token, newPassword);

        DefaultUser updatedUser = defaultUserRepository.findByUsername(testUser.getUsername()).orElse(null);
        assertNotNull(updatedUser);

        assertTrue(passwordEncoder.matches(newPassword, updatedUser.getPassword()));
    }

}