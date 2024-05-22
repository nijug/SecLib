package com.seclib.userRoles.permissions;

import com.seclib.config.AuthorizationProperties;
import com.seclib.exception.UserException;
import com.seclib.user.model.BaseUser;
import com.seclib.user.model.DefaultUser;
import com.seclib.user.service.DefaultUserService;
import jakarta.servlet.http.HttpSession;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.List;

@Aspect
@Component
public class PermissionAspect {


    private final AuthorizationProperties authorizationProperties;

    private final DefaultUserService userService;

    public PermissionAspect(AuthorizationProperties authorizationProperties, DefaultUserService userService) {
        this.authorizationProperties = authorizationProperties;
        this.userService = userService;
    }

    @Before("execution(* com.seclib..*(..)) && args(session,..)")
    public void checkPermission(JoinPoint joinPoint, HttpSession session) throws NoSuchMethodException {
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            throw new SecurityException("User ID not found in session");
        }

        DefaultUser user = userService.findById(userId);
        if (user == null) {
            throw new SecurityException("User not found");
        }

        String role = user.getRole();
        AuthorizationProperties.RoleProperties roleProperties = authorizationProperties.getRoles().get(role);
        if (roleProperties == null) {
            throw new SecurityException("User does not have required permissions");
        }
        //todo: change exceptions, remember to change the test

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        if (method.isAnnotationPresent(RequiredPermissions.class)) {
            RequiredPermissions requiredPermissions = method.getAnnotation(RequiredPermissions.class);
            String[] permissions = requiredPermissions.value();

            for (String requiredPermission : permissions) {
                if (!roleProperties.getPermissions().contains(requiredPermission)) {
                    throw new SecurityException("Permission " + requiredPermission + " is not declared in the application properties");
                }
            }
        }
    }

    private DefaultUser getCurrentUser(HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");
        return userService.findById(userId);
    }
}
