package com.seclib.ipBlocking;

import org.springframework.data.repository.CrudRepository;

public interface BlockedIpRepository extends CrudRepository<BlockedIp, String> {
}