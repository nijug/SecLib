package com.seclib;

import com.seclib.config.AuthorizationProperties;
import com.seclib.loginAttempt.repository.DefaultLoginAttemptRepository;
import com.seclib.loginAttempt.service.DefaultLoginAttemptService;
import com.seclib.userRoles.permissions.PermissionAspect;
import com.seclib.userRoles.permissions.RequiredPermissions;
import com.seclib.user.model.DefaultUser;
import com.seclib.user.service.DefaultUserService;
import jakarta.servlet.http.HttpSession;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@SpringBootTest
class RolePermissionTests {

    @Mock
    private AuthorizationProperties authorizationProperties;

    @Mock
    private DefaultUserService userService;

    @Mock
    private HttpSession session;

    @Mock
    private JoinPoint joinPoint;

    @Mock
    private MethodSignature methodSignature;

    private PermissionAspect permissionAspect;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        permissionAspect = new PermissionAspect(authorizationProperties, userService);

        Map<String, AuthorizationProperties.RoleProperties> roles = new HashMap<>();
        AuthorizationProperties.RoleProperties roleProperties = new AuthorizationProperties.RoleProperties();
        roleProperties.setPermissions(Arrays.asList("READ"));
        roles.put("admin", roleProperties);

        when(authorizationProperties.getRoles()).thenReturn(roles);
    }

    @Test
    void testCheckPermission() throws NoSuchMethodException {
        DefaultUser user= new DefaultUser("testUser", "Password123!");
        user.setRole("admin");

        when(session.getAttribute("userId")).thenReturn(1L);
        when(userService.findById(1L)).thenReturn(user);
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(joinPoint.getArgs()).thenReturn(new Object[] { session }); // Make sure the session is included in the joinPoint arguments
        when(methodSignature.getMethod()).thenReturn(TestClass.class.getMethod("methodWithRequiredPermissions", HttpSession.class));

        assertDoesNotThrow(() -> permissionAspect.checkPermission(joinPoint));
        verify(userService, times(1)).findById(1L);
    }

    @Test
    void testCheckPermissionWithoutRequiredPermissions() throws NoSuchMethodException {
        DefaultUser user = new DefaultUser("testUser", "Password123!");
        user.setRole("user"); // The "user" role does not have the "READ" permission

        when(session.getAttribute("userId")).thenReturn(1L);
        when(userService.findById(1L)).thenReturn(user);
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(joinPoint.getArgs()).thenReturn(new Object[] { session }); // Make sure the session is included in the joinPoint arguments
        when(methodSignature.getMethod()).thenReturn(TestClass.class.getMethod("methodWithRequiredPermissions", HttpSession.class));

        assertThrows(SecurityException.class, () -> permissionAspect.checkPermission(joinPoint));
    }

    @Test
    void testCheckPermissionWithUserNotFound() {
        when(session.getAttribute("userId")).thenReturn(1L);
        when(userService.findById(1L)).thenReturn(null);
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(joinPoint.getArgs()).thenReturn(new Object[] { session }); // Make sure the session is included in the joinPoint arguments

        assertThrows(SecurityException.class, () -> permissionAspect.checkPermission(joinPoint));
    }

    @Test
    void testCheckPermissionWithoutUserIdInSession() {
        when(session.getAttribute("userId")).thenReturn(null); // The session does not contain a user ID
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(joinPoint.getArgs()).thenReturn(new Object[] { session }); // Make sure the session is included in the joinPoint arguments

        assertThrows(SecurityException.class, () -> permissionAspect.checkPermission(joinPoint));
    }

    @Test
    void testCheckPermissionWithoutRequiredPermissionsAnnotation() throws NoSuchMethodException {
        DefaultUser user = new DefaultUser("testUser", "Password123!");
        user.setRole("admin");

        when(session.getAttribute("userId")).thenReturn(1L);
        when(userService.findById(1L)).thenReturn(user);
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(joinPoint.getArgs()).thenReturn(new Object[] { session }); // Make sure the session is included in the joinPoint arguments
        when(methodSignature.getMethod()).thenReturn(TestClass.class.getMethod("methodWithoutRequiredPermissions", HttpSession.class));

        assertDoesNotThrow(() -> permissionAspect.checkPermission(joinPoint));
    }

    public static class TestClass {
        @RequiredPermissions("READ")
        public void methodWithRequiredPermissions(HttpSession session) {
        }

        public void methodWithoutRequiredPermissions(HttpSession session) {
        }
    }

}
