package com.pranav.auth.repository;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Reads the {@code v_user_permissions} view to flatten a user's active roles/permissions/region/
 * zone for embedding as JWT claims. Uses plain JDBC since the view has no natural JPA entity
 * mapping (it is a projection, not a table).
 */
@Repository
public class UserPermissionQueryRepository {

    private final JdbcTemplate jdbcTemplate;

    public UserPermissionQueryRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public UserClaims loadClaims(Long userId) {
        List<UserClaimRow> rows = jdbcTemplate.query(
                "SELECT role_name, permission_code, region_code, zone_code FROM v_user_permissions WHERE user_id = ?",
                (rs, rowNum) -> new UserClaimRow(
                        rs.getString("role_name"),
                        rs.getString("permission_code"),
                        rs.getString("region_code"),
                        rs.getString("zone_code")),
                userId);

        Set<String> roles = new LinkedHashSet<>();
        Set<String> permissions = new LinkedHashSet<>();
        String region = null;
        String zone = null;

        for (UserClaimRow row : rows) {
            if (row.roleName() != null && !"DIRECT".equals(row.roleName())) {
                roles.add(row.roleName());
            }
            if (row.permissionCode() != null) {
                permissions.add(row.permissionCode());
            }
            if (region == null && row.regionCode() != null) {
                region = row.regionCode();
            }
            if (zone == null && row.zoneCode() != null) {
                zone = row.zoneCode();
            }
        }

        return new UserClaims(roles, permissions, region, zone);
    }

    private record UserClaimRow(String roleName, String permissionCode, String regionCode, String zoneCode) {
    }

    public record UserClaims(Set<String> roles, Set<String> permissions, String regionCode, String zoneCode) {
    }
}
