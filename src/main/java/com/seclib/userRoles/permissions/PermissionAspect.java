package com.seclib.userRoles.permissions;

import com.seclib.config.AuthorizationProperties;
import com.seclib.user.model.BaseUser;
import com.seclib.user.model.DefaultUser;
import com.seclib.user.service.DefaultUserService;
import com.seclib.userRoles.model.BaseRole;
import com.seclib.userRoles.model.DefaultRole;
import com.seclib.userRoles.service.BaseRoleService;
import com.seclib.userRoles.service.DefaultRoleService;
import jakarta.servlet.http.HttpSession;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.hibernate.boot.model.internal.XMLContext;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Aspect
@Component
public class PermissionAspect {

    private final DefaultRoleService roleService;

    private final AuthorizationProperties authorizationProperties;

    private final DefaultUserService userService;

    public PermissionAspect(DefaultRoleService roleService, AuthorizationProperties authorizationProperties, DefaultUserService userService) {
        this.roleService = roleService;
        this.authorizationProperties = authorizationProperties;
        this.userService = userService;
    }

    @Before("execution(* *(..)) && args(session,..)")
    public void checkPermission(JoinPoint joinPoint, HttpSession session) throws NoSuchMethodException {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        if (method.isAnnotationPresent(RequiredPermissions.class)) {
            RequiredPermissions requiredPermissions = method.getAnnotation(RequiredPermissions.class);
            String[] permissions = requiredPermissions.value();

            DefaultRole currentUserRole = getCurrentUserRole(session);
            for (String requiredPermission : permissions) {
                List<String> allDeclaredPermissions = authorizationProperties.getRoles().values().stream()
                        .flatMap(role -> role.getPermissions().stream())
                        .collect(Collectors.toList());
                if (!allDeclaredPermissions.contains(requiredPermission)) {
                    throw new SecurityException("Permission " + requiredPermission + " is not declared in the application properties");
                }

                if (!roleService.hasPermission(currentUserRole, Permission.valueOf(requiredPermission))) {
                    throw new SecurityException("Permission denied");
                }
            }
        }
    }

    private DefaultRole getCurrentUserRole(HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");
        DefaultUser user = userService.findById(userId);
        String roleName = user.getRole();

        AuthorizationProperties.RoleProperties roleProperties = authorizationProperties.getRoles().get(roleName);
        Set<Permission> permissions = roleProperties.getPermissions().stream()
                .map(Permission::valueOf)
                .collect(Collectors.toSet());

        return new DefaultRole(roleName, permissions);
    }
}