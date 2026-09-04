package com.pranav.auth.repository;

import com.pranav.auth.entity.TokenBlacklistEntry;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklistEntry, Long> {

    boolean existsByTokenJti(String tokenJti);
}
