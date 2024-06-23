package com.seclib.userRoles.permissions;

import com.seclib.config.AuthorizationProperties;

import com.seclib.user.model.DefaultUser;
import com.seclib.user.service.DefaultUserService;
import jakarta.servlet.http.HttpSession;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import java.lang.reflect.Method;


@Aspect
@Component
public class PermissionAspect {


    private final AuthorizationProperties authorizationProperties;

    private final DefaultUserService userService;

    private static final Logger logger = LoggerFactory.getLogger(PermissionAspect.class);


    public PermissionAspect(AuthorizationProperties authorizationProperties, DefaultUserService userService) {
        this.authorizationProperties = authorizationProperties;
        this.userService = userService;
    }

    @Before("@annotation(RequiredPermissions)")
    public void checkPermission(JoinPoint joinPoint) throws NoSuchMethodException {
        logger.info("Checking permissions for method: " + joinPoint.getSignature());

        HttpSession session = null;
        for (Object arg : joinPoint.getArgs()) {
            if (arg instanceof HttpSession) {
                session = (HttpSession) arg;
                break;
            }
        }

        if (session == null) {
            logger.error("No session found");
            throw new SecurityException("No session found");
        }

        Long userId = (Long) session.getAttribute("userId");
        String role;
        if (userId == null) {
            role = (String) session.getAttribute("role");
            logger.info("Role from session: " + role); // Log the role from the session
        } else {
            DefaultUser user = userService.findById(userId);
            if (user == null) {
                logger.error("User not found");
                throw new SecurityException("User not found");
            }
            role = user.getRole();
        }
        logger.info("Role names defined in the application properties: " + authorizationProperties.getRoles().keySet());

        AuthorizationProperties.RoleProperties roleProperties = authorizationProperties.getRoles().get(role);
        if (roleProperties == null) {
            logger.error("User does not have required permissions");
            throw new SecurityException("User does not have required permissions");
        }

        logger.info("Permissions for role " + role + ": " + roleProperties.getPermissions());

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        if (method.isAnnotationPresent(RequiredPermissions.class)) {
            RequiredPermissions requiredPermissions = method.getAnnotation(RequiredPermissions.class);
            String[] permissions = requiredPermissions.value();

            if (permissions != null) {
                for (String requiredPermission : permissions) {
                    if (!roleProperties.getPermissions().contains(requiredPermission)) {
                        logger.error("Permission {} is not declared in the application properties", requiredPermission);
                        throw new SecurityException("Permission " + requiredPermission + " is not declared in the application properties");
                    }
                }
            } else {
                throw new SecurityException("No permissions specified in RequiredPermissions annotation");
            }
        }

        logger.info("Permission check passed for user with ID {}", userId);
    }
}